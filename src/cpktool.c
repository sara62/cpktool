#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <cpk/ecies.h>
#include <cpk/cpk.h>


/* distribution */
//#define CPK_NO_SETUP	1
//#define CPK_NO_GENKEY	1

#ifdef WIN32
#include <io.h>
#include <direct.h>
#define PATH_SEP "\\"
#define F_OK 0
#define access _access
#define mkdir _mkdir
#else
#include <unistd.h>
#define PATH_SEP "/"
#define mkdir(path) mkdir(path,0770)
#endif

#include "cpktool.h"
#include "cpktool_stub.h"

#define CPKTOOL_BUFSIZE		BUFSIZ
#define CPKTOOL_FBSIZE		32

static char *curve_name = "prime192v1";
static const EVP_CIPHER *default_cipher = NULL;
static const EVP_MD *default_md = NULL;

static BIO *bio_err = NULL;
static char *prog = "cpk";
static char *path_home = NULL;
static char *path_master = NULL;
static char *path_param = NULL;
static char *path_identity = NULL;
static char *path_signkey = NULL;
static char *path_decryptkey = NULL;


static char *cur_time(char *buffer, int len);
static off_t file_size(const char *file);
static int swip_file(const char *file);

static int init_paths(const char *user_home, const char *prog_home);
static void free_paths(void);
static int create_home(void);
static CPK_MASTER_SECRET *load_master_file(const char *file);
static CPK_PUBLIC_PARAMS *load_param_file(const char *file);
static int print_param(CPK_PUBLIC_PARAMS *param, BIO *out);
static EVP_PKEY *load_key_bio(BIO *bio, const char *pass);
static EVP_PKEY *load_key_file(const char *file, const char *pass);
static int save_key_bio(EVP_PKEY *pkey, BIO *bio, const char *pass);
static int save_key_file(EVP_PKEY *pkey, const char *file, const char *pass);
static EVP_PKEY *key_from_text(const char *str, int hex);
static char *key_to_text(EVP_PKEY *pkey, int hex);
static int sign_text_key(char *sig, const char *in, int inlen, EVP_MD_CTX *ctx, EVP_PKEY *pkey);
static char *sign_ctx_key(EVP_MD_CTX *ctx, EVP_PKEY *pkey);
static char *sign_bio_key(BIO *bio, EVP_PKEY *pkey);
static int verify_ctx_param(EVP_MD_CTX *ctx, const char *signature,
	const char *signer, CPK_PUBLIC_PARAMS *param);
static int verify_bio_param(BIO *bio, const char *signature, const char *signer,
	CPK_PUBLIC_PARAMS *param);
static unsigned char *encrypt_bin_param(const unsigned char *in, int inlen,
	int *outlen, const char *id, CPK_PUBLIC_PARAMS *param);
static char *encrypt_b64_param(const unsigned char *in, int inlen, const char *id,
	CPK_PUBLIC_PARAMS *param);
static unsigned char *decrypt_bin_key(const unsigned char *in, int inlen,
	int *outlen, EVP_PKEY *pkey);
static unsigned char *decrypt_b64_key(const char *in, int *outlen, EVP_PKEY *pkey);
static int64_t sym_encrypt_common(BIO *in, int64_t inlen, BIO *out,
	const unsigned char *key, int enc);
#define sym_encrypt(in,inlen,out,key)	sym_encrypt_common(in,inlen,out,key,1)
#define sym_decrypt(in,out,key)		sym_encrypt_common(in,-1,out,key,0)
static int64_t envelope_encrypt(BIO *in, int64_t inlen, BIO *out, char **rcpts,
	int num_rcpts, int base64);
static int envelope_decrypt(BIO *in, BIO *out, const char *pass);
static int get_file_stub(const char *file, char **type, unsigned char **stub,
	int *len);
static off_t get_payload_pos(const char *file);



int cpktool_init(const char *user_home, const char *prog_home, char *prog_name,
	FILE *err_fp)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	if (prog_name)
		prog = prog_name;
	
	if (err_fp)
		bio_err = BIO_new_fp(err_fp, BIO_NOCLOSE);
	else	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	
	default_cipher = EVP_aes_128_cbc();
	default_md = EVP_sha1();

	if (init_paths(user_home, prog_home) < 0) {
		BIO_printf(bio_err, "%s: initialize paths failed\n", prog);
		return -1;
	}

	return 0;
}

void cpktool_exit(void)
{
	ERR_free_strings();
	EVP_cleanup();

	if (bio_err) {
		BIO_free(bio_err);
		bio_err = NULL;
	}
	prog = NULL;
	free_paths();
}

/*
 * create ~/.cpk
 * create ~/.cpk/master_secret
 * create ~/.cpk/public_params
 * create ~/.cpk/log 
 */
int cpktool_setup(const char *domainid)
{
	int ret = -1;
#ifndef CPK_NO_SETUP
	BIO *bio_master = NULL;
	BIO *bio_param = NULL;
	CPK_MASTER_SECRET *master = NULL;
	CPK_PUBLIC_PARAMS *params = NULL;
	EC_KEY *ec_key;
	EVP_PKEY *pkey = NULL;
	X509_ALGOR *map_algor = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(domainid);
	
	if (create_home() < 0) {
		BIO_printf(bio_err, "%s: create home directory failed\n", prog);
		goto end;
	}
	if (!(bio_master = BIO_new_file(path_master, "w"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog,
			path_master);
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(bio_param = BIO_new_file(path_param, "w"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog,
			path_param);
		ERR_print_errors(bio_err);
		goto end;
	}

	if (!(ec_key = EC_KEY_new_by_curve_name(OBJ_sn2nid(curve_name)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	EC_GROUP_set_asn1_flag((EC_GROUP *)EC_KEY_get0_group(ec_key), OPENSSL_EC_NAMED_CURVE);
	
	EC_KEY_generate_key(ec_key);
	if (!(pkey = EVP_PKEY_new())) {
		EC_KEY_free(ec_key);
		ERR_print_errors(bio_err);
		goto end;		
	}
	EVP_PKEY_assign_EC_KEY(pkey, ec_key);
	
	if (!(map_algor = CPK_MAP_new_default())){
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (!(master = CPK_MASTER_SECRET_create(domainid, pkey, map_algor))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (i2d_CPK_MASTER_SECRET_bio(bio_master, master) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (!(params = CPK_MASTER_SECRET_extract_public_params(master))) {
		ERR_print_errors(bio_err);
		goto end;	
	}
	if (i2d_CPK_PUBLIC_PARAMS_bio(bio_param, params) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 0;

end:
	if (master) CPK_MASTER_SECRET_free(master);
	if (params) CPK_PUBLIC_PARAMS_free(params);
	if (bio_master) BIO_free(bio_master);
	if (bio_param) BIO_free(bio_param);
	if (pkey) EVP_PKEY_free(pkey);
	if (map_algor) X509_ALGOR_free(map_algor);
#endif
	return ret;
}

int cpktool_import_master(const char *file)
{
	int ret = -1;
	BIO *in = NULL;
	BIO *out = NULL;
	CPK_MASTER_SECRET *master;
	
	OPENSSL_assert(path_home);
	if (create_home() < 0) {
		BIO_printf(bio_err, "%s: create home directory failed\n", prog);
		goto end;
	}

	if (file) {
		if (!(in = BIO_new_file(file, "r"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n",
				prog, file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);

	OPENSSL_assert(path_master);
	if (!(out = BIO_new_file(path_master, "w"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog,
			path_master);
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (!(master = d2i_CPK_MASTER_SECRET_bio(in, NULL))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (i2d_CPK_MASTER_SECRET_bio(out, master) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 0;
	
end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	if (master) CPK_MASTER_SECRET_free(master);
	
	return ret;
}

int cpktool_export_master(const char *file)
{
	int ret = -1;
	BIO *out = NULL;
	CPK_MASTER_SECRET *master = NULL;
	
	OPENSSL_assert(path_home);
	
	if (file) {
		if (!(out = BIO_new_file(file, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	OPENSSL_assert(path_master);
	if (!(master = load_master_file(path_master))) {
		BIO_printf(bio_err, "%s: load master-secret failed\n",
			prog);
		goto end;
	}
	
	if (i2d_CPK_MASTER_SECRET_bio(out, master) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 0;
end:
	if (out) BIO_free(out);
	if (master) CPK_MASTER_SECRET_free(master);
	return ret;
}

int cpktool_print_master(const char *file)
{
	int ret = -1;
	CPK_MASTER_SECRET *master = NULL;
	BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	OPENSSL_assert(path_home);
	
	if (!file) {
		OPENSSL_assert(path_master);
		file = path_master;
	}
	
	if (!(master = load_master_file(file))) {
		BIO_printf(bio_err, "%s: load master-secret %s failed\n",
			prog, file);
		goto end;
	}
	/*
	if (!CPK_MASTER_SECRET_print(out, master, 0, 0)) {
		BIO_printf(bio_err, "%s: this error should not happen!\n", prog);
		goto end;
	}
	*/
	
	ret = 0;
end:
	if (master) CPK_MASTER_SECRET_free(master);
	if (out) BIO_free(out);
	return ret;
}

/*
 * return -1 inner error
 * return -2 invalid params file
 */
int cpktool_import_params(const char *file)
{
	int ret = -1;
	BIO *in = NULL;
	BIO *out = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	
	OPENSSL_assert(path_home);
	if (create_home() < 0) {
		BIO_printf(bio_err, "%s: create home directory failed\n", prog);
		goto end;
	}

	if (file) {
		if (!(in = BIO_new_file(file, "r"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n",
				prog, file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);

	OPENSSL_assert(path_param);
	if (!(out = BIO_new_file(path_param, "w"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog,
			path_param);
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (!(param = d2i_CPK_PUBLIC_PARAMS_bio(in, NULL))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (i2d_CPK_PUBLIC_PARAMS_bio(out, param) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 0;
	
end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	if (param) CPK_PUBLIC_PARAMS_free(param);
	
	return ret;
}

int cpktool_export_params(const char *file)
{
	int ret = -1;
	BIO *out = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	
	OPENSSL_assert(path_home);
	
	if (file) {
		if (!(out = BIO_new_file(file, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	OPENSSL_assert(path_param);
	if (!(param = load_param_file(path_param))) {
		BIO_printf(bio_err, "%s: load public parameters failed\n",
			prog);
		goto end;
	}
	
	if (i2d_CPK_PUBLIC_PARAMS_bio(out, param) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 0;
end:
	if (out) BIO_free(out);
	if (param) CPK_PUBLIC_PARAMS_free(param);
	return ret;
}

int cpktool_print_params(const char *file)
{
	int ret = -1;
	CPK_PUBLIC_PARAMS *param = NULL;
	BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	OPENSSL_assert(path_home);
	
	if (!file) {
		OPENSSL_assert(path_param);
		file = path_param;
	}
	
	if (!(param = load_param_file(file))) {
		BIO_printf(bio_err, "%s: load public-parameters %s failed\n",
			prog, file);
		goto end;
	}
	/*
	if (!CPK_PUBLIC_PARAMS_print(out, param, 0, 0)) {
		BIO_printf(bio_err, "%s: this error should not happen!\n", prog);
		goto end;
	}
	*/	

	ret = 0;
end:
	if (param) CPK_PUBLIC_PARAMS_free(param);
	if (out) BIO_free(out);
	return ret;
}

int cpktool_genkey(const char *id, const char *file, const char *pass)
{
	int ret = -1;
#ifndef CPK_NO_GENKEY
	BIO *out = NULL;
	CPK_MASTER_SECRET *master = NULL;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(id);
	OPENSSL_assert(pass);
	OPENSSL_assert(strlen(pass) > 0);
	OPENSSL_assert(path_master);
	
	if (file) {
		if (!(out = BIO_new_file(file, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				file);
			goto end;
		}
	} else
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	if (!(master = load_master_file(path_master))) {
		BIO_printf(bio_err, "%s: load master-secret file %s failed\n",
			prog, path_master);
		goto end;
	}
	if (!(pkey = CPK_MASTER_SECRET_extract_private_key(master, id))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (save_key_bio(pkey, out, pass) < 0) {
		BIO_printf(bio_err, "%s: output key to %s failed\n", prog,
			file ? file : "stdout");
		goto end;
	}
	
	ret = 0;
end:
	if (out) BIO_free(out);
	if (master) CPK_MASTER_SECRET_free(master);
	if (pkey) EVP_PKEY_free(pkey);
#endif
	return ret;
}

char *cpktool_gen_key(const char *id, const char *pass)
{
	char *ret = NULL;
#ifndef CPK_NO_GENKEY
	BIO *out = BIO_new(BIO_s_mem()); 
	CPK_MASTER_SECRET *master = NULL;
	EVP_PKEY *pkey = NULL;

	if (!(master = load_master_file(path_master))) {
		goto end;
	}

	if (!(pkey = CPK_MASTER_SECRET_extract_private_key(master, id))) {
		goto end;
	}
	if (save_key_bio(pkey, out, pass) < 0) {
		goto end;
	}
end:
#endif
	return NULL;
}

int cpktool_print_key(const char *file, const char *pass)
{
	int ret = -1;
	BIO *in = NULL;
	BIO *out = NULL;
	EVP_PKEY *pkey = NULL;
	char *text = NULL;
	int hex = 1;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(pass);
	
	if (file) {
		if (!(in = BIO_new_file(file, "r"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n",
				prog, file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);
	
	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	if (!(pkey = load_key_bio(in, pass))) {
		BIO_printf(bio_err, "%s: load key %s failed\n", prog, file);
		goto end;
	}
	if (!(text = key_to_text(pkey, hex))) {
		BIO_printf(bio_err, "%s: convert key to text failed\n", prog);
		goto end;
	}
	BIO_printf(out, "%s\n", text);
	ret = 0;

end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	if (pkey) EVP_PKEY_free(pkey);
	if (text) OPENSSL_free(text);
	return ret;
}

int cpktool_set_identity(const char *id)
{
	int ret = -1;
	BIO *bio_id = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(id);
	OPENSSL_assert(strlen(id) > 0 && strlen(id) <= CPK_MAX_ID_LENGTH);
	
	if (create_home() < 0) {
		BIO_printf(bio_err, "%s: create home directory %s failed\n",
			prog, path_home);
		goto end;
	}
	if (strlen(id) > CPK_MAX_ID_LENGTH) {
		BIO_printf(bio_err, "%s: identity %s too long\n", prog, id);
		goto end;
	}
	if (!(bio_id = BIO_new_file(path_identity, "w"))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_puts(bio_id, id) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	ret = 0;
end:
	if (bio_id) BIO_free(bio_id);
	return ret;
}

/*
 * return string should be free-ed by caller
 */
char *cpktool_get_identity(void)
{
	char *ret = NULL;
	BIO *bio_id = NULL;
	char buffer[CPK_MAX_ID_LENGTH + 1];
	char *p;
	
	OPENSSL_assert(path_home);
	
	if (!(bio_id = BIO_new_file(path_identity, "r"))) {
		// FIXME: identity file may not exist
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_gets(bio_id, buffer, sizeof(buffer) - 1) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if((p = strchr(buffer, '\n')) != NULL)
		*p = '\0';
	if (strlen(buffer) <= 0 || strlen(buffer) > CPK_MAX_ID_LENGTH) {
		BIO_printf(bio_err, "%s: identity too long\n", prog);
		goto end;
	}
	
	if (!(ret = OPENSSL_malloc(strlen(buffer) + 1))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	strcpy(ret, buffer);

end:
	if (bio_id) BIO_free(bio_id);
	return ret;
}

int cpktool_import_sign_key(const char *file, const char *pass)
{
	int ret = -1;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	char *signer = NULL;
	char *signature = NULL;
	char *text = "signed message";
	BIO *bio_mem1 = NULL;
	BIO *bio_mem2 = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(pass);
	OPENSSL_assert(strlen(pass) > 0);

	if (file) {
		if (!(in = BIO_new_file(file, "r"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);
	
	if (!(pkey = load_key_bio(in, pass))) {
		BIO_printf(bio_err, "%s: load key %s failed\n", prog, file);
		goto end;
	}
	if (!(param = load_param_file(path_param))) {
		BIO_printf(bio_err, "%s: load public parameters failed\n", prog);
		goto end;
	}
	if (access(path_identity, F_OK) < 0) {
		BIO_printf(bio_err, "%s: identity not initialized\n", prog);
		goto end;
	}
	if (!(signer = cpktool_get_identity())) {
		BIO_printf(bio_err, "%s: get identity failed\n", prog);
		goto end;
	}
	if (!(bio_mem1 = BIO_new_mem_buf(text, strlen(text)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(bio_mem2 = BIO_new_mem_buf(text, strlen(text)))) {
		ERR_print_errors(bio_err);
		goto end;
	}	
	if (!(signature = sign_bio_key(bio_mem1, pkey))) {
		BIO_printf(bio_err, "%s: sign failed\n", prog);
		goto end;
	}
	if (verify_bio_param(bio_mem2, signature, signer, param) < 0) {
		BIO_printf(bio_err, "%s: key verification failed\n",
			prog);
		goto end;
	}
 
	if (save_key_file(pkey, path_signkey, pass) < 0) {
		BIO_printf(bio_err, "%s: save key failed\n", prog);
		goto end;
	}
	
	ret = 0;

end:
	if (in) BIO_free(in);
	if (pkey) EVP_PKEY_free(pkey);
	if (param) CPK_PUBLIC_PARAMS_free(param);
	if (signer) OPENSSL_free(signer);
	if (signature) OPENSSL_free(signature);
	if (bio_mem1) BIO_free(bio_mem1);
	if (bio_mem2) BIO_free(bio_mem2);
	return ret;
}

int cpktool_export_sign_key(const char *pass, const char *file,
	const char *new_pass)
{
	int ret = -1;
	EVP_PKEY *pkey = NULL;
	
	if (access(path_signkey, F_OK) < 0) {
		BIO_printf(bio_err, "%s: sign key not initialized\n", prog);
		goto end;
	}
	if (!(pkey = load_key_file(path_signkey, pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (save_key_file(pkey, file, new_pass) < 0) {
		BIO_printf(bio_err, "%s: save key failed\n", prog);
		goto end;
	}
	ret = 0;	
end:
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

int cpktool_change_sign_password(const char *old_pass, const char *new_pass)
{
	int ret = -1;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(old_pass);
	OPENSSL_assert(new_pass);
	
	if (access(path_signkey, F_OK) < 0) {
		BIO_printf(bio_err, "%s: sign key not initialized\n", prog);
		goto end;
	}
	if (!(pkey = load_key_file(path_signkey, old_pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (save_key_file(pkey, path_signkey, new_pass) < 0) {
		BIO_printf(bio_err, "%s: save key failed\n", prog);
		goto end;
	}
	ret = 0;	
end:
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

int cpktool_delete_sign_key(const char *pass)
{
        int ret = -1;
        EVP_PKEY *pkey = NULL;
        
	if (access(path_signkey, F_OK) < 0) {
		BIO_printf(bio_err, "%s: sign key not exist\n", prog);
		goto end;
	}
        if (!(pkey = load_key_file(path_signkey, pass))) {
                BIO_printf(bio_err, "%s: wrong password\n", prog);
                goto end;
        }
        if (remove(path_signkey) < 0) {
                BIO_printf(bio_err, "%s: delete failed\n", prog);
                goto end;
        }
        ret = 0;
end:
        if (pkey) EVP_PKEY_free(pkey);
        return ret;
}

int cpktool_import_decrypt_key(const char *file, const char *pass)
{
	int ret = -1;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	char *id = NULL;
	unsigned char *ciphertext = NULL;
	unsigned char *plaintext = NULL;
	char *text = "to be encrypted message";
	int len, len2;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(pass);
	
	if (file) {
		if (!(in = BIO_new_file(file, "r"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog, file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);
	
	if (!(pkey = load_key_bio(in, pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (!(param = load_param_file(path_param))) {
		BIO_printf(bio_err, "%s: load public parameters failed\n", prog);
		goto end;
	}
	
	if (access(path_identity, F_OK) < 0) {
		BIO_printf(bio_err, "%s: identity not initialized\n", prog);
		goto end;
	}
	if (!(id = cpktool_get_identity())) {
		BIO_printf(bio_err, "%s: get identity failed\n", prog);
		goto end;
	}
	if (!(ciphertext = encrypt_bin_param((unsigned char *)text,
		strlen(text), &len, id, param))) {
		BIO_printf(bio_err, "%s: identity-based encryption failed\n", prog);
		goto end;
	}
	if (!(plaintext = decrypt_bin_key(ciphertext, len, &len2, pkey))) {
		BIO_printf(bio_err, "%s: identity-based decryption failed\n", prog);
		goto end;
	}
	if (len2 != strlen(text) || memcmp(text, plaintext, strlen(text))) {
		BIO_printf(bio_err, "%s: key verification failed\n", prog);
		goto end;
	}
	
	if (save_key_file(pkey, path_decryptkey, pass) < 0) {
		BIO_printf(bio_err, "%s: save key failed\n", prog);
		goto end;
	}
	ret = 0;

end:
	if (in) BIO_free(in);
	if (pkey) EVP_PKEY_free(pkey);
	if (param) CPK_PUBLIC_PARAMS_free(param);
	if (id) OPENSSL_free(id);
	if (ciphertext) OPENSSL_free(ciphertext);
	if (plaintext) OPENSSL_free(plaintext);
	return ret;
}

int cpktool_export_decrypt_key(const char *pass, const char *file,
	const char *new_pass)
{
	int ret = -1;
	EVP_PKEY *pkey = NULL;
	
	if (access(path_decryptkey, F_OK) < 0) {
		BIO_printf(bio_err, "%s: decrypt key not initialized\n", prog);
		goto end;
	}
	if (!(pkey = load_key_file(path_decryptkey, pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (save_key_file(pkey, file, new_pass) < 0) {
		BIO_printf(bio_err, "%s: save key failed\n", prog);
		goto end;
	}
	ret = 0;	
end:
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

int cpktool_change_decrypt_password(const char *old_pass, const char *new_pass)
{
	int ret = -1;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(old_pass);
	OPENSSL_assert(new_pass);
	
	if (access(path_decryptkey, F_OK) < 0) {
		BIO_printf(bio_err, "%s: decrypt key not initialized\n", prog);
		goto end;
	}
	if (!(pkey = load_key_file(path_decryptkey, old_pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (save_key_file(pkey, path_decryptkey, new_pass) < 0) {
		BIO_printf(bio_err, "%s: save key failed\n", prog);
		goto end;
	}
	ret = 0;	
end:
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

int cpktool_delete_decrypt_key(const char *pass)
{
        int ret = -1;
        EVP_PKEY *pkey = NULL;
        
	if (access(path_decryptkey, F_OK) < 0) {
		BIO_printf(bio_err, "%s: decrypt key not exist\n", prog);
		goto end;
	}
        if (!(pkey = load_key_file(path_decryptkey, pass))) {
                BIO_printf(bio_err, "%s: wrong password\n", prog);
                goto end;
        }
        if (remove(path_decryptkey) < 0) {
                BIO_printf(bio_err, "%s: delete failed\n", prog);
                goto end;
        }
        ret = 0;
end:
        if (pkey) EVP_PKEY_free(pkey);
        return ret;
}

char *cpktool_sign_text(const char *text, int textlen, const char *pass)
{
	char *ret = NULL;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(text);
	if (textlen < 0)
		textlen = strlen(text);
	OPENSSL_assert(textlen);
	OPENSSL_assert(pass);
	
	if (!(bio = BIO_new_mem_buf((char *)text, textlen))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(pkey = load_key_file(path_signkey, pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (!(ret = sign_bio_key(bio, pkey))) {
		BIO_printf(bio_err, "%s: sign failed\n", prog);
		goto end;
	}
end:
	if (bio) BIO_free(bio);
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

int cpktool_verify_text(const char *text, int textlen, const char *signature,
	const char *signer)
{
	int ret = -1;
	BIO *bio = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(text);
	if (textlen < 0)
		textlen = strlen(text);
	OPENSSL_assert(textlen);
	OPENSSL_assert(signature);
	OPENSSL_assert(strlen(signature) > 0);
	OPENSSL_assert(signer);
	OPENSSL_assert(strlen(signer) > 0);
	
	if (!(bio = BIO_new_mem_buf((char *)text, textlen))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(param = load_param_file(path_param))) {
		BIO_printf(bio_err, "%s: load public parameters failed\n", prog);
		goto end;
	}
	if ((ret = verify_bio_param(bio, signature, signer, param)) < 0) {
		goto end;
	}
end:
	if (bio) BIO_free(bio);
	if (param) CPK_PUBLIC_PARAMS_free(param);
	return ret;
}

int cpktool_batch_sign_file(const char *file, const char *pass)
{
	int ret = -1;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	unsigned char line[4096];
	char sig[256];
	EVP_MD_CTX ctx;

	EVP_MD_CTX_init(&ctx);

	if (file) {
		if (!(bio = BIO_new_file(file, "rb"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog, file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		bio = BIO_new_fp(stdin, BIO_NOCLOSE);

	if (!(pkey = load_key_file(path_signkey, pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}

	while (BIO_gets(bio, line, sizeof(line)) > 0) {
		char *p = strchr(line, '\n');
		if (p)
			*p = 0;
		printf("%s: ", line);
		sign_text_key(sig, line, -1, &ctx, pkey);
		printf("%s\n", sig);
	}

	ret = 1;
end:
	if (bio) BIO_free(bio);
	EVP_MD_CTX_cleanup(&ctx);
	return ret;
}

char *cpktool_sign_file(const char *file, const char *pass)
{
	char *ret = NULL;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(pass);
	
	if (file) {
		if (!(bio = BIO_new_file(file, "rb"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				file);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		bio = BIO_new_fp(stdin, BIO_NOCLOSE);
		
	if (!(pkey = load_key_file(path_signkey, pass))) {
		BIO_printf(bio_err, "%s: load key failed\n", prog);
		goto end;
	}
	if (!(ret = sign_bio_key(bio, pkey))) {
		BIO_printf(bio_err, "%s: sign failed\n", prog);
		goto end;
	}
end:
	if (bio) BIO_free(bio);
	return ret;
}

int cpktool_verify_file(const char *file, const char *signature,
	const char *signer)
{
	int ret = -1;
	BIO *bio = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;

	OPENSSL_assert(path_home);
	OPENSSL_assert(signature);
	OPENSSL_assert(strlen(signature) > 0);
	OPENSSL_assert(signer);
	OPENSSL_assert(strlen(signer) > 0);	
	
	if (file) {
		if (!(bio = BIO_new_file(file, "rb"))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		bio = BIO_new_fp(stdin, BIO_NOCLOSE);
		
	if (!(param = load_param_file(path_param))) {
		BIO_printf(bio_err, "%s: load public parameters failed\n", prog);
		goto end;
	}
	if ((ret = verify_bio_param(bio, signature, signer, param)) < 0) {
		goto end;
	}
end:
	if (bio) BIO_free(bio);
	if (param) CPK_PUBLIC_PARAMS_free(param);
	return ret;
}

char *cpktool_encrypt_text(const char *text, int textlen, const char *id)
{
	char *ret = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(text);
	OPENSSL_assert(id);
	OPENSSL_assert(strlen(id) > 0);
	if (textlen < 0)
		textlen = strlen(text);
	OPENSSL_assert(textlen > 0);
	
	if (!(param = load_param_file(path_param))) {
		BIO_printf(bio_err, "%s: load public parameters failed\n", prog);
		goto end;
	}
	if (!(ret = encrypt_b64_param((unsigned char *)text, textlen, id, param))) {
		BIO_printf(bio_err, "%s: identity-based encryption failed\n",
			prog);
		goto end;
	}
	
end:
	if (param) CPK_PUBLIC_PARAMS_free(param);
	return ret;
}

char *cpktool_decrypt_text(const char *text, int *outlen, const char *pass)
{
	unsigned char *ret = NULL;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(text); // check strlen(text);
	OPENSSL_assert(outlen);
	OPENSSL_assert(pass);
	
	if (!(pkey = load_key_file(path_decryptkey, pass))) {
		BIO_printf(bio_err, "%s: load key %s failed\n", prog,
			path_decryptkey);
		goto end;
	}
	if (!(ret = decrypt_b64_key(text, outlen, pkey))) {
		BIO_printf(bio_err, "%s: identity-based decrypt failed\n", prog);
		goto end;
	}
end:
	if (pkey) EVP_PKEY_free(pkey);
	return (char *)ret;
}

char *cpktool_envelope_encrypt_text(const char *text, int textlen, char **rcpts,
	int num_rcpts)
{
	char *ret = NULL;
	int len;
	BIO *in = NULL;
	BIO *out = NULL;
	char *p;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(text);
	if (textlen < 0)
		textlen = strlen(text);
	OPENSSL_assert(textlen > 0);
	OPENSSL_assert(rcpts);
	OPENSSL_assert(num_rcpts > 0);
	
	if (!(in = BIO_new_mem_buf((char *)text, textlen))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(out = BIO_new(BIO_s_mem()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (envelope_encrypt(in, textlen, out, rcpts, num_rcpts, 1) < 0) {
		BIO_printf(bio_err, "%s: error\n", prog);
		goto end;
	}
	
	if ((len = (int)BIO_get_mem_data(out, &p)) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(ret = OPENSSL_malloc(len))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_read(out, ret, len) != len) {
		OPENSSL_free(ret);
		ERR_print_errors(bio_err);
		goto end;
	}
end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	return ret;
}

char *cpktool_envelope_decrypt_text(const char *text, int textlen, int *outlen,
	const char *pass)
{
	char *ret = NULL;
	BIO *in = NULL;
	BIO *out = NULL;
	char *p;
	int len;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(text);
	if (textlen < 0)
		textlen = strlen(text);
	OPENSSL_assert(textlen > 0);
	OPENSSL_assert(outlen);
	OPENSSL_assert(pass);
	OPENSSL_assert(strlen(pass) > 0);
		
	if (!(in = BIO_new_mem_buf((char *)text, textlen))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(out = BIO_new(BIO_s_mem()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (envelope_decrypt(in, out, pass) < 0) {
		goto end;
	}
	if ((len = BIO_get_mem_data(out, &p)) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	*outlen = len;
	if (!(ret = OPENSSL_malloc(len))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_read(out, ret, len) != len) {
		OPENSSL_free(ret);
		ERR_print_errors(bio_err);
		goto end;
	}
end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	return ret;
}

int cpktool_envelope_encrypt_file(const char *infile, const char *outfile, 
	char **rcpts, int num_rcpts, int base64)
{
	int ret = -1;
	int64_t inlen;
	BIO *in = NULL;
	BIO *out = NULL;
		
	OPENSSL_assert(path_home);
	OPENSSL_assert(rcpts);
	OPENSSL_assert(num_rcpts > 0);
	
	if (rcpts == NULL || *rcpts == NULL || num_rcpts <= 0) {
		BIO_printf(bio_err, "%s: invalid arguments\n", prog);
		goto end;
	}
	
	if (infile) {
		struct stat st;
		if (!(in = BIO_new_file(infile, "r"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				infile);
			ERR_print_errors(bio_err);
			goto end;
		}
		if (stat(infile, &st) < 0) {
			BIO_printf(bio_err, "%s: fstat() failed: %s\n", prog,
				strerror(errno));
			goto end;
		}
		if ((inlen = (int64_t)st.st_size) <= 0) {
			BIO_printf(bio_err, "%s: invalid input length\n", prog);
			goto end;
		}		
	} else {
		int len;
		char buffer[CPKTOOL_BUFSIZE];
		
		if (!(in = BIO_new(BIO_s_mem()))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		inlen = 0;
		while ((len = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
			if (BIO_write(in, buffer, len) != len) {
				ERR_print_errors(bio_err);
				goto end;
			}
			inlen += len;
		}
	}

	if (outfile) {
		if (!(out = BIO_new_file(outfile, "wb"))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	if (envelope_encrypt(in, inlen, out, rcpts, num_rcpts, base64) < 0) {
		BIO_printf(bio_err, "%s: shit\n", prog);
		goto end;
	}
	
	ret = 0;

end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	return ret;
}

int cpktool_envelope_decrypt_file(const char *infile, const char *outfile,
	const char *pass)
{
	int ret = -1;
	BIO *in = NULL;
	BIO *out = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(pass);
	OPENSSL_assert(strlen(pass) > 0);
	
	if (!pass) {
		BIO_printf(bio_err, "%s: invalid arguments\n", prog);
		goto end;
	}
	
	if (infile) {
		if (!(in = BIO_new_file(infile, "rb"))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);
	
	if (outfile) {
		if (!(out = BIO_new_file(outfile, "wb"))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	if (envelope_decrypt(in, out, pass) < 0) {
		goto end;
	}
	
	ret = 0;
	
end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	return ret;
}

int cpktool_format_preserve_sign_file(const char *infile, const char *outfile, 
	const char *pass)
{
	int ret = -1;
	BIO *in = NULL;
	BIO *out = NULL;
	BIO *bio_md = NULL;
	EVP_MD_CTX *ctx;
	char buffer[CPKTOOL_BUFSIZE];
	int len;
	int64_t len64;
	char *id;
	EVP_PKEY *pkey = NULL;
	char *signature = NULL;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(infile);
	OPENSSL_assert(pass);

	if (!(in = BIO_new_file(infile, "r"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog, infile);
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(bio_md = BIO_new(BIO_f_md()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!BIO_set_md(bio_md, default_md)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(bio_md = BIO_push(bio_md, in))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (!(id = cpktool_get_identity())) {
		goto end;
	}
	if (!(pkey = load_key_file(path_signkey, pass))) {
		goto end;
	}
		
	if (outfile) {
		if (!(out = BIO_new_file(outfile, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				outfile);
			ERR_print_errors(bio_err);
			goto end;
		}
		while ((len = BIO_read(bio_md, buffer, sizeof(buffer))) > 0) {
			if (BIO_write(out, buffer, len) != len) {
				ERR_print_errors(bio_err);
				goto end;
			}
		}
	} else {
		while (BIO_read(bio_md, buffer, sizeof(buffer)) > 0)
			;
		BIO_free(in);
		in = NULL;
		if (!(out = BIO_new_file(infile, "a"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				infile);
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	if (!BIO_get_md_ctx(bio_md, &ctx)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(signature = sign_ctx_key(ctx, pkey))) {
		BIO_printf(bio_err, "%s: sign_ctx() failed\n", prog);
		goto end;
	}
	
	len64 = 0;
	if ((len = BIO_puts(out, "CPK SignerInfos\n")) != 
		sizeof("CPK SignerInfos")) {
		ERR_print_errors(bio_err);
		goto end;
	}
	len64 += len;
	if ((len = BIO_printf(out, "%s:%s\n\n", id, signature)) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	len64 += len;
	
	if (BIO_printf(out, "CPK EOF %23lld\n", len64) != 32) {
		ERR_print_errors(bio_err);
		goto end;
	}

	ret = 0;
	
end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	if (bio_md) BIO_free(bio_md);
	if (pkey) EVP_PKEY_free(pkey);

	return ret;
}

int cpktool_format_preserve_verify_file(const char *file)
{
	int ret = -1;
	off_t payload_pos;
	BIO *in = NULL;
	BIO *bio_md = NULL;
	CPK_PUBLIC_PARAMS *param = NULL;
	char buffer[CPKTOOL_BUFSIZE];
	int len;
	EVP_MD_CTX *ctx;
	char *p;
	int r;
	
	
	OPENSSL_assert(path_home);
	
	if ((payload_pos = get_payload_pos(file)) < 0) {
		BIO_printf(bio_err, "%s: invalid file format\n", prog);
		goto end;
	}
	
	if (!(in = BIO_new_file(file, "r"))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(param = load_param_file(path_param))) {
		goto end;
	}

	if (!(bio_md = BIO_new(BIO_f_md()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!BIO_set_md(bio_md, default_md)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!BIO_push(bio_md, in)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while (payload_pos > 0) {
		len = payload_pos < sizeof(buffer) ? payload_pos : sizeof(buffer);
		if ((len = BIO_read(bio_md, buffer, len)) < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
		payload_pos -= len;
	}
	if (!BIO_get_md_ctx(bio_md, &ctx)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_gets(in, buffer, sizeof(buffer)) <= 0) {
		BIO_printf(bio_err, "%s: read nothing\n", prog);
		goto end;
	}	
	if (memcmp(buffer, "CPK SignerInfos", strlen("CPK SignerInfos"))) {
		BIO_printf(bio_err, "%s: invalid SignerInfos: %s\n", prog,
			buffer);
		goto end;
	}

	for (;;) {
		if (BIO_gets(in, buffer, sizeof(buffer)) <= 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!strcmp(buffer, "\n")) {
			break;	
		}
		if (!(p = strchr(buffer, ':'))) {
			BIO_printf(bio_err, "%s: invalid SignerInfo: %s\n",
				prog, buffer);
			goto end;
		}
		*p++ = '\0';
		if (!p || strlen(p) <= 0) {
			BIO_printf(bio_err, "%s: invalid signature format\n",
				prog);
			goto end;
		}
		r = verify_ctx_param(ctx, p, buffer, param);
		printf("%s:%s\n", buffer, r < 0 ? "failed" : "success");
	}
	
	ret = 0;
	
end:
	return ret;
}

int cpktool_format_preserve_encrypt_file(const char *infile, const char *outfile,
	char **rcpts, int num_rcpts, int base64)
{
	int ret = -1;
	char *tmpfile = NULL;
	BIO *in = NULL;
	BIO *out = NULL;
	char *type;
	unsigned char *stub;
	int len;
	off_t flen;
	
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(infile);
	
	if ((flen = file_size(infile)) <= 0) {
		goto end;
	}
	if (!(in = BIO_new_file(infile, "r"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog, infile);
		ERR_print_errors(bio_err);
		goto end;
	}

	if (outfile) {
		if (!(out = BIO_new_file(outfile, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				outfile);
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {	
		if (!(tmpfile = OPENSSL_malloc(strlen(infile) + 
			sizeof(".cpk")))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		strcpy(tmpfile, infile);
		strcat(tmpfile, ".cpk");
		if (!(out = BIO_new_file(tmpfile, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				tmpfile);
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	
	if (get_file_stub(infile, &type, &stub, &len) < 0) {
		BIO_printf(bio_err, "%s: unsupported file type\n", prog);
		goto end;
	}
	if (BIO_write(out, stub, len) != len) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (envelope_encrypt(in, flen, out, rcpts, num_rcpts, base64) < 0) {
		BIO_printf(bio_err, "%s: envelop() failed\n", prog);
		goto end;
	}
	if (BIO_printf(out, "CPK EOF %23d\n", BIO_tell(out) - len) != 32) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	BIO_free(out);
	out = NULL;
	
	if (tmpfile) {
		if (remove(infile) < 0) {
			BIO_printf(bio_err, "%s: remove plaintext failed: %s\n",
				prog, strerror(errno));
			goto end;
		}
		if (rename(tmpfile, infile) < 0) {
			BIO_printf(bio_err, "%s: rename ciphertext failed: %s\n", prog,
				strerror(errno));
			goto end;
		}
	}
	
	ret = 0;

end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	if (tmpfile) OPENSSL_free(tmpfile);

	return ret;
}

int cpktool_format_preserve_decrypt_file(const char *infile, const char *outfile,
	const char *pass)
{
	int ret = -1;
	BIO *in = NULL;
	BIO *out = NULL;
	char *tmpfile = NULL;
	off_t payload_pos;
	
	OPENSSL_assert(path_home);
	OPENSSL_assert(infile);
	
	if ((payload_pos = get_payload_pos(infile)) < 0) {
		BIO_printf(bio_err, "%s: shit\n", prog);
		goto end;
	}
	if (!(in = BIO_new_file(infile, "r"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog, infile);
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_seek(in, (int)payload_pos) < 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	
	if (outfile) {
		if (!(out = BIO_new_file(outfile, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				outfile);
			ERR_print_errors(bio_err);
			goto end;		
		}
	} else {
		if (!(tmpfile = OPENSSL_malloc(strlen(infile) + 
			sizeof(".cpk")))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		strcpy(tmpfile, infile);
		strcat(tmpfile, ".cpk");
		if (!(out = BIO_new_file(tmpfile, "w"))) {
			BIO_printf(bio_err, "%s: open file %s failed\n", prog,
				tmpfile);
			ERR_print_errors(bio_err);
			goto end;		
		}
	}
	
	if (envelope_decrypt(in, out, pass) < 0) {
		BIO_printf(bio_err, "%s: deenvelop() failed\n", prog);
		goto end;
	}
	
	BIO_free(out);
	out = NULL;
	
	if (tmpfile) {
		if (remove(infile) < 0) {
			BIO_printf(bio_err, "%s: remove plaintext failed: %s\n", prog,
				strerror(errno));
			goto end;
		}
		if (rename(tmpfile, infile) < 0) {
			BIO_printf(bio_err, "%s: rename ciphertext failed: %s\n", prog,
				strerror(errno));
			goto end;
		}
	}
	
	ret = 0;

end:
	if (in) BIO_free(in);
	if (out) BIO_free(out);
	if (tmpfile) OPENSSL_free(tmpfile);
	
	return ret;
}

int cpktool_add_policy_entry(const char *policy, const char *comment, int flags)
{
        return 0;
}

int   cpktool_remove_policy_entry(int entry)
{
        return 0;
}

int cpktool_get_policy_entry_init(void)
{
        return 0;
}

int cpktool_get_policy_entry_next(char **policy, char **comment, int *flags)
{
        return 0;
}

int cpktool_get_policy_entry_final(void)
{
        return 0;
}

int cpktool_validate_identity(const char *id)
{
        return 0;
}

int cpktool_revoke_identity(const char *id, int reason)
{
        return 0;
}

int cpktool_get_identity_state(const char *id)
{
        return 0;
}
int cpktool_get_identity_metadata(const char *id, void *meta)
{
        return 0;
}

int cpktool_get_identity_init(const char *template, int flags)
{
        return 0;
}

int cpktool_get_identity_next(void)
{
        return 0;
}

int cpktool_get_identity_exit()
{
        return 0;
}

char *cpktool_get_current_identity(const char *id)
{
        return NULL;
}

int cpktool_import_revocation_list(const char *file)
{
        return 0;
}

int cpktool_export_revocation_list(const char *file)
{
        return 0;
}

int cpktool_print_revocation_list(void)
{
        return 0;
}	

/****************************************************************************
 *                          Static Functions                                *
 ****************************************************************************/

static char *cur_time(char *buffer, int len)
{
	time_t t;
	struct tm *tm;
	
	OPENSSL_assert(buffer);	
	if ((t = time(NULL)) < 0) {
		BIO_printf(bio_err, "%s: time() failed: %s\n", prog,
			strerror(errno));
		return NULL;
	}
	tm = gmtime(&t);
	strftime(buffer, len, "%Y%m%d%H%M%S", tm);
	return buffer;
}

static off_t file_size(const char *file)
{
	struct stat st;
	if (stat(file, &st) < 0) {
		BIO_printf(bio_err, "%s: get file %s stat failed: %s\n", prog,
			file, strerror(errno));
		return -1;
	}
	if (st.st_size < 0) {
		BIO_printf(bio_err, "%s: file %s size error\n", prog, file);
		return -1;
	}
	return st.st_size;
}

static int swip_file(const char *file)
{
	int ret = -1;
	if ((ret = remove(file)) < 0) {
		BIO_printf(bio_err, "%s: swip file %s failed: %s\n", prog, file,
			strerror(errno));
		goto end;
	}
	ret = 0;
end:
	return ret;
}

#if defined(WIN32)

#include <userenv.h>
#pragma comment(lib, "userenv.lib")

char *get_user_home()
{
	static char buffer[MAX_PATH];
	DWORD length = sizeof(buffer)/sizeof(buffer[0]);
	HANDLE token = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		fprintf(stderr, "shit\n");
		return NULL;
	}
	if (!GetUserProfileDirectoryA(token, buffer, &length)) {
		fprintf(stderr, "shit2\n");
		return NULL;
	}
	return buffer;
}

#elif defined(ANDROID)

char *get_user_home()
{
	return "/sdcard";
}

#else

/*
 * getenv("HOME") return "/home/username" or NULL
 * return value of getenv() should not be freed.
 */
char *get_user_home()
{
	return getenv("HOME");
}

#endif

static int init_paths(const char *user_home, const char *prog_home)
{
	int home_len;
	int total_len;
	
	if (!user_home) {
		
		if (!(user_home = get_user_home())) {
			BIO_printf(bio_err, "%s: set home directory failed %s\n",
				prog, user_home);
			goto end;
		}
	}
	if (!prog_home)
		prog_home = ".cpk";
	
	/* ~/.cpk/ */
	if (path_home)
		OPENSSL_free(path_home);
	home_len = strlen(user_home) + strlen(prog_home) + strlen("//");
	if (!(path_home = OPENSSL_malloc(home_len + 1))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	strcpy(path_home, user_home);
	strcat(path_home, PATH_SEP);
	strcat(path_home, prog_home);
	strcat(path_home, PATH_SEP);

	/* ~/.cpk/master_secret */
	if (path_master)
		OPENSSL_free(path_master);
	total_len = home_len + sizeof("master_secret");
	if (!(path_master = OPENSSL_malloc(total_len))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	strcpy(path_master, path_home);
	strcat(path_master, "master_secret");

	/* ~/.cpk/public_params */
	if (path_param)
		OPENSSL_free(path_param);
	total_len = home_len + sizeof("public_params");
	if (!(path_param = OPENSSL_malloc(total_len))) {
		ERR_print_errors(bio_err);
		goto end;	
	}
	strcpy(path_param, path_home);
	strcat(path_param, "public_params");
	
	/* ~/.cpk/identity */
	if (path_identity)
		OPENSSL_free(path_identity);
	total_len = home_len + sizeof("identity");
	if (!(path_identity = OPENSSL_malloc(total_len))) {
		ERR_print_errors(bio_err);
		goto end;	
	}
	strcpy(path_identity, path_home);
	strcat(path_identity, "identity");	
	
	/* ~/.cpk/sign_key */
	if (path_signkey)
		OPENSSL_free(path_signkey);
	total_len = home_len + sizeof("sign_key");
	if (!(path_signkey = OPENSSL_malloc(total_len))) {
		ERR_print_errors(bio_err);
		goto end;	
	}
	strcpy(path_signkey, path_home);
	strcat(path_signkey, "sign_key");
	
	/* ~/.cpk/decrypt_key */
	if (path_decryptkey)
		OPENSSL_free(path_decryptkey);
	total_len = home_len + sizeof("decrypt_key");
	if (!(path_decryptkey = OPENSSL_malloc(total_len))) {
		ERR_print_errors(bio_err);
		goto end;	
	}
	strcpy(path_decryptkey, path_home);
	strcat(path_decryptkey, "decrypt_key");		

	/* return before end because free_paths() 
	 * shuold be called when failed 
	 */
	return 0;
end:
	free_paths();
	return -1;
}

static void free_paths(void)
{
	if (path_home) {
		OPENSSL_free(path_home);
		path_home = NULL;
	}
	if (path_master) {
		OPENSSL_free(path_master);
		path_master = NULL;
	}
	if (path_param) {
		OPENSSL_free(path_param);
		path_param = NULL;
	}
	if (path_identity) {
		OPENSSL_free(path_identity);
		path_identity = NULL;
	}	
	if (path_signkey) {
		OPENSSL_free(path_signkey);
		path_signkey = NULL;
	}	
	if (path_decryptkey) {
		OPENSSL_free(path_decryptkey);
		path_decryptkey = NULL;
	}
}

/*
 * create_home() only required by
 *	cpktool_setup()
 *	cpktool_import_params()
 *	cpktool_set_id();
 */
static int create_home(void)
{
	if (access(path_home, F_OK) < 0) {
		if (mkdir(path_home) < 0) {
			BIO_printf(bio_err, "%s: mkdir(%s) failed: %s\n",
				prog, path_home, strerror(errno));
			return -1;
		}
		return 0;
	}
	return 0;
}

static CPK_MASTER_SECRET *load_master_file(const char *file)
{
	CPK_MASTER_SECRET *master = NULL;
	BIO *bio = NULL;
	
	OPENSSL_assert(file);
	if (!(bio = BIO_new_file(file, "rb"))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(master = d2i_CPK_MASTER_SECRET_bio(bio, NULL))) {
		BIO_printf(bio_err, "%s: parse master secret %s failed\n",
			prog, file);
		ERR_print_errors(bio_err);
		goto end;
	}
end:
	if (bio) BIO_free(bio);
	return master;
}

static CPK_PUBLIC_PARAMS *load_param_file(const char *file)
{
	CPK_PUBLIC_PARAMS *param = NULL;
	BIO *bio = NULL;
	
	OPENSSL_assert(file);
	if (!(bio = BIO_new_file(file, "r"))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(param = d2i_CPK_PUBLIC_PARAMS_bio(bio, NULL))) {
		BIO_printf(bio_err, "%s: parse public parameters %s failed\n",
			prog, file);
		ERR_print_errors(bio_err);
		goto end;
	}
end:
	if (bio) BIO_free(bio);
	return param;
}

/*
 * version: 1
 * domainId: www.cpksecurity.com/smalltest
 * pkeyalgor: ec
 * pkeyparam: secp192k1
 * mapalgor: 
 */
static int print_param(CPK_PUBLIC_PARAMS *param, BIO *out)
{
	
	return 0;
}

static EVP_PKEY *load_key_bio(BIO *bio, const char *pass)
{
	X509_SIG *p8 = NULL;
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(bio);
	OPENSSL_assert(pass);	
	
	if (!(p8 = PEM_read_bio_PKCS8(bio, NULL, NULL, NULL))) {
		BIO_printf(bio_err, "%s: parse PKCS8 failed\n", prog);
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(p8inf = PKCS8_decrypt(p8, pass, strlen(pass)))) {
		BIO_printf(bio_err, "%s: decrypt PKCS8 failed\n", prog);
		goto end;
	}
	if (!(pkey = EVP_PKCS82PKEY(p8inf))) {
		BIO_printf(bio_err, "%s: convert PKCS8 to PKEY failed\n", prog);
		ERR_print_errors(bio_err);
		goto end;
	}

end:
	if (p8) X509_SIG_free(p8);
	if (p8inf) PKCS8_PRIV_KEY_INFO_free(p8inf);
	return pkey;
}

static EVP_PKEY *load_key_file(const char *file, const char *pass)
{
	EVP_PKEY *ret = NULL;
	BIO *bio = NULL;
	
	OPENSSL_assert(file);
	OPENSSL_assert(pass);	
	
	if (!(bio = BIO_new_file(file, "r"))) {
		ERR_print_errors(bio_err);
		return NULL;
	}
	ret = load_key_bio(bio, pass);
	BIO_free(bio);
	return ret;
}

static int save_key_bio(EVP_PKEY *pkey, BIO *bio, const char *pass)
{
	int ret = -1;
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	X509_SIG *p8 = NULL;
	
	OPENSSL_assert(pkey);
	OPENSSL_assert(bio);
	OPENSSL_assert(pass);
	OPENSSL_assert(strlen(pass) > 0);
	
	if (!(p8inf = EVP_PKEY2PKCS8(pkey))) {
		BIO_printf(bio_err, "%s: PKEY to PKCS8 failed\n", prog);
		ERR_print_errors(bio_err);
		goto end;
	}
	/*
	if (!PKCS8_add_keyusage(p8info, KEY_SIG)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	*/
	if (!(p8 = PKCS8_encrypt(-1, default_cipher, pass,
		strlen(pass), NULL, 0, PKCS12_DEFAULT_ITER, p8inf))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	PEM_write_bio_PKCS8(bio, p8);
	ret = 0;
end:
	if (p8inf) PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (p8) X509_SIG_free(p8);
	return ret;
}

static int save_key_file(EVP_PKEY *pkey, const char *file, const char *pass)
{
	int ret = -1;
	BIO *bio = NULL;
	
	OPENSSL_assert(pkey);
	OPENSSL_assert(file);
	OPENSSL_assert(pass);
	OPENSSL_assert(strlen(pass) > 0);
	
	if (!(bio = BIO_new_file(file, "w"))) {
		ERR_print_errors(bio_err);
		return -1;
	}
	ret = save_key_bio(pkey, bio, pass);
	BIO_free(bio);
	return ret;
}

static EVP_PKEY *key_from_text(const char *str, int hex)
{	
	int e = 1;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec_key = NULL;
	BIGNUM *bn = NULL;
	
	OPENSSL_assert(bio_err);
	if ((hex ? BN_hex2bn(&bn, str) : BN_dec2bn(&bn, str)) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	OPENSSL_assert(curve_name);
	if (!(ec_key = EC_KEY_new_by_curve_name(OBJ_sn2nid(curve_name)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(EC_KEY_set_private_key(ec_key, bn))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(pkey = EVP_PKEY_new())) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	e = 0;
end:
	if (e && pkey) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	if (ec_key) EC_KEY_free(ec_key);
	if (bn) BN_free(bn);
	return pkey;
}

static char *key_to_text(EVP_PKEY *pkey, int hex)
{
	char *ret = NULL;
	const BIGNUM *bn;
	
	OPENSSL_assert(pkey);
	
	if (pkey->type == EVP_PKEY_EC)
		bn = EC_KEY_get0_private_key((EC_KEY *)EVP_PKEY_get0(pkey));
	else if (pkey->type == EVP_PKEY_DSA)
		bn = ((const DSA *)EVP_PKEY_get0(pkey))->priv_key;
	else {
		BIO_printf(bio_err, "%s: invalid key type\n", prog);
		return NULL;
	}
	if (!(ret = hex ? BN_bn2hex(bn) : BN_bn2dec(bn))) {
		ERR_print_errors(bio_err);
		return NULL;
	}
	return ret;
}

static int sign_text_key(char *sig, const char *in, int inlen, EVP_MD_CTX *ctx, EVP_PKEY *pkey)
{
	int ret = -1;
	unsigned char signature[128];
	int len;

	EVP_SignInit_ex(ctx, default_md, NULL);
	EVP_SignUpdate(ctx, in, inlen > 0 ? inlen : strlen(in));
	EVP_SignFinal(ctx,  signature, &len, pkey);
	EVP_EncodeBlock((unsigned char *)sig, signature, len);
	ret = 0;
	return ret;	
}

static char *sign_ctx_key(EVP_MD_CTX *ctx, EVP_PKEY *pkey)
{
	char *ret = NULL;
	unsigned char signature[128];
	unsigned int len;
	
	OPENSSL_assert(ctx);
	OPENSSL_assert(pkey);
	
	if (!EVP_SignFinal(ctx, signature, &len, pkey)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(ret = OPENSSL_malloc(EVP_ENCODE_LENGTH(len)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	EVP_EncodeBlock((unsigned char *)ret, signature, len);
end:
	return ret;
}

static char *sign_bio_key(BIO *bio, EVP_PKEY *pkey)
{
	char *ret = NULL;
	BIO *bio_md = NULL;
	EVP_MD_CTX *ctx;
	char buffer[CPKTOOL_BUFSIZE];
	
	OPENSSL_assert(bio);
	OPENSSL_assert(pkey);
	
	if (!(bio_md = BIO_new(BIO_f_md()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!BIO_set_md(bio_md, default_md)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(bio = BIO_push(bio_md, bio))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while (BIO_read(bio, buffer, sizeof(buffer)) > 0)
		;
	if (!BIO_get_md_ctx(bio_md, &ctx)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = sign_ctx_key(ctx, pkey);
	
end:
	if (bio_md) BIO_free(bio_md);
	return ret;
}

static int verify_ctx_param(EVP_MD_CTX *ctx, const char *signature,
	const char *signer, CPK_PUBLIC_PARAMS *param)
{
	int ret = -1;
	EVP_PKEY *pkey = NULL;
	unsigned char *buffer = NULL;
	int len, r;
	
	OPENSSL_assert(ctx);
	OPENSSL_assert(signature);
	OPENSSL_assert(strlen(signature) > 0);
	OPENSSL_assert(signer);
	OPENSSL_assert(strlen(signer) > 0);
	OPENSSL_assert(param);
	
	if (!(pkey = CPK_PUBLIC_PARAMS_extract_public_key(param, signer))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(buffer = OPENSSL_malloc(strlen(signature)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	len = EVP_DecodeBlock(buffer, (const unsigned char *)signature,
		strlen(signature));
	if ((r = EVP_VerifyFinal(ctx, buffer, len, pkey)) < 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = (r == 1) ? 0 : -2;
end:
	if (pkey) EVP_PKEY_free(pkey);
	if (buffer) OPENSSL_free(buffer);
	return ret;
}

static int verify_bio_param(BIO *bio, const char *signature, const char *signer,
	CPK_PUBLIC_PARAMS *param)
{
	int ret = -1;
	BIO *bio_md = NULL;
	EVP_MD_CTX *ctx;
	unsigned char buffer[CPKTOOL_BUFSIZE];
	
	OPENSSL_assert(bio);
	OPENSSL_assert(signature);
	OPENSSL_assert(strlen(signature) > 0);
	OPENSSL_assert(signer);
	OPENSSL_assert(strlen(signer) > 0);
	OPENSSL_assert(param);

	if (!(bio_md = BIO_new(BIO_f_md()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!BIO_set_md(bio_md, default_md)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(bio = BIO_push(bio_md, bio))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while (BIO_read(bio_md, buffer, sizeof(buffer)) > 0)
		;
	if (!BIO_get_md_ctx(bio_md, &ctx)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = verify_ctx_param(ctx, signature, signer, param);
end:
	if (bio_md) BIO_free(bio_md);
	return ret;
}

static unsigned char *encrypt_bin_param(const unsigned char *in, int inlen,
	int *outlen, const char *id, CPK_PUBLIC_PARAMS *param)
{
	int e = 1;
	EVP_PKEY *pkey = NULL;	
	unsigned char *buf = NULL;
	unsigned char *p;
	int len;
	
	OPENSSL_assert(in);
	OPENSSL_assert(inlen > 0);
	OPENSSL_assert(outlen);
	OPENSSL_assert(id);
	OPENSSL_assert(strlen(id) > 0 && strlen(id) <= CPK_MAX_ID_LENGTH);
	OPENSSL_assert(param);

	if (!(pkey = CPK_PUBLIC_PARAMS_extract_public_key(param, id))) {
		ERR_print_errors(bio_err);
		goto end;
	}

	if (pkey->type == EVP_PKEY_EC) {
	
		ECIES_CIPHERTEXT_VALUE *cv = NULL;
		ECIES_PARAMS ecies;
		ecies.kdf_md = default_md;
		ecies.sym_cipher = NULL;
		ecies.mac_md = default_md;
		
		if (!(cv = ECIES_do_encrypt(&ecies, in, inlen,
			(EC_KEY *)EVP_PKEY_get0(pkey)))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL)) < 0) {
			ECIES_CIPHERTEXT_VALUE_free(cv);
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!(buf = OPENSSL_malloc(len))) {
			ECIES_CIPHERTEXT_VALUE_free(cv);
			ERR_print_errors(bio_err);
			goto end;
		}
		p = buf;
		i2d_ECIES_CIPHERTEXT_VALUE(cv, &p);
		ECIES_CIPHERTEXT_VALUE_free(cv);
	
	} else {
		BIO_printf(bio_err, "%s: invalid key type\n", prog);
		goto end;
	}
	
	e = 0;
	*outlen = len;
	
end:
	if (pkey) EVP_PKEY_free(pkey);
	if (e && buf) {
		OPENSSL_free(buf);
		buf = NULL;
	}
	return buf;
}

static char *encrypt_b64_param(const unsigned char *in, int inlen, const char *id,
	CPK_PUBLIC_PARAMS *param)
{
	char *ret = NULL;
	unsigned char *buffer = NULL;
	int len;
	
	OPENSSL_assert(in);
	OPENSSL_assert(inlen > 0);
	OPENSSL_assert(id);
	OPENSSL_assert(strlen(id) > 0 && strlen(id) <= CPK_MAX_ID_LENGTH);
	OPENSSL_assert(param);
	
	if (!(buffer = encrypt_bin_param(in, inlen, &len, id, param))) {
		BIO_printf(bio_err, "%s: encrypt() failed\n", prog);
		goto end;
	}
	if (!(ret = OPENSSL_malloc(EVP_ENCODE_LENGTH(len)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	EVP_EncodeBlock((unsigned char *)ret, buffer, len);
end:
	if (buffer) OPENSSL_free(buffer);
	return ret;
}

static unsigned char *decrypt_bin_key(const unsigned char *in, int inlen,
	int *outlen, EVP_PKEY *pkey)
{
	int ok = 0;
	unsigned char *out = NULL;
	size_t len;
	
	OPENSSL_assert(in);
	OPENSSL_assert(inlen > 0);
	OPENSSL_assert(outlen);
	OPENSSL_assert(pkey);
	
	if (pkey->type == EVP_PKEY_EC) {
		
		ECIES_CIPHERTEXT_VALUE *cv = NULL;
		const unsigned char *p = in;
		ECIES_PARAMS ecies;
		ecies.kdf_md = default_md;
		ecies.sym_cipher = NULL;
		ecies.mac_md = default_md;
		
		if (!(cv = d2i_ECIES_CIPHERTEXT_VALUE(NULL, &p, (long)inlen))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (cv->ciphertext->length <= 0) {
			ECIES_CIPHERTEXT_VALUE_free(cv);
			BIO_printf(bio_err, "%s: invalid ciphertext\n", prog);
			goto end;
		}
		len = cv->ciphertext->length;
		if (!(out = OPENSSL_malloc(len))) {
			ECIES_CIPHERTEXT_VALUE_free(cv);
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!ECIES_do_decrypt(cv, &ecies, out, &len,
			(EC_KEY *)EVP_PKEY_get0(pkey))) {
			ECIES_CIPHERTEXT_VALUE_free(cv);
			ERR_print_errors(bio_err);
			goto end;
		}
		ECIES_CIPHERTEXT_VALUE_free(cv);
		*outlen = (int)len;
		
	} else {
		BIO_printf(bio_err, "%s: invalid key type\n", prog);
		goto end;
	}
	
	ok = 1;
end:
	if (!ok && out) {
		OPENSSL_free(out);
		out = NULL;
	}
	return out;
}

static unsigned char *decrypt_b64_key(const char *in, int *outlen, EVP_PKEY *pkey)
{
	unsigned char *ret = NULL;
	unsigned char *buffer = NULL;
	int len;

	OPENSSL_assert(in);
	OPENSSL_assert(strlen(in) > 0);
	OPENSSL_assert(outlen);
	OPENSSL_assert(pkey);
	
	if (!(buffer = OPENSSL_malloc(strlen(in)))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if ((len = EVP_DecodeBlock(buffer, (const unsigned char *)in, strlen(in))) <= 0) {
		ERR_print_errors(bio_err);
		BIO_printf(bio_err, "%s %d: error on decode base64 ciphertext\n", __FILE__, __LINE__);
		goto end;
	}

	ret = decrypt_bin_key(buffer, len, outlen, pkey);
end:
	if (buffer) OPENSSL_free(buffer);
	return ret;
}

static int64_t sym_encrypt_common(BIO *in, int64_t inlen, BIO *out,
	const unsigned char *key, int enc)
{
	int ok = 0;
	const EVP_CIPHER *cipher = EVP_aes_128_cfb();
	int len = EVP_CIPHER_iv_length(cipher);
	int64_t total_len = 0;
	char buffer[CPKTOOL_BUFSIZE];
	BIO *bio_md = NULL;
	BIO *bio_cipher = NULL;
	
	OPENSSL_assert(in);
	OPENSSL_assert(out);
	OPENSSL_assert(key);

	if (enc) {
		RAND_bytes((unsigned char *)buffer, len);
		if (BIO_write(out, buffer, len) != len) {
			ERR_print_errors(bio_err);
			goto end;
		}
		total_len += len;
		
		len = sizeof(int64_t);
		if (BIO_write(out, (char *)&inlen, len) != len) {
			ERR_print_errors(bio_err);
			goto end;
		}
		total_len += len;
		
	} else {
		if ((len = BIO_read(in, buffer, len)) != 16) {
			BIO_printf(bio_err, "%s: invalid format: not enough "
				"length for symmetric encryption inital vector %d\n",
				prog, len);
			
			ERR_print_errors(bio_err);
			BIO_printf(bio_err, "end\n");
			goto end;
		}
		if (BIO_read(in, (char *)&inlen, sizeof(inlen))
			!= sizeof(inlen)) {
			BIO_printf(bio_err, "%s: invalid format: not enough "
				"length for symmetric encrypted data length\n",
				prog);
			ERR_print_errors(bio_err);
			goto end;
		}
		if (inlen <= 0) {
			BIO_printf(bio_err, "%s: invalid format: non positive "
				"length\n", prog);
			goto end;
		}
	}
	
	if (!(bio_md = BIO_new(BIO_f_md()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	BIO_set_md(bio_md, default_md);
	out = BIO_push(bio_md, out);
	
	if (!(bio_cipher = BIO_new(BIO_f_cipher()))) {
		ERR_print_errors(bio_err);
		goto end;
	}
	BIO_set_cipher(bio_cipher, cipher, key, (unsigned char *)buffer, enc);
	out = BIO_push(bio_cipher, out);
	
	while (inlen > 0) {
		len = inlen < sizeof(buffer) ? inlen : sizeof(buffer);
		if ((len = BIO_read(in, buffer, len)) <= 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (BIO_write(out, buffer, len) != len) {
			ERR_print_errors(bio_err);
			goto end;
		}
		inlen -= len;
		total_len += len;
	}
	/*
	 * BIO_flush is needed here because BIO_free(out) will not called
	 * inside this function.
	 */
	BIO_flush(out);
	
	/*
	 * todo: we need to calculate the mac
	 */
	ok = 1;
end:
	if (bio_md) BIO_free(bio_md);
	if (bio_cipher) BIO_free(bio_cipher);
	return ok ? total_len : -1;
}

static int64_t envelope_encrypt(BIO *in, int64_t inlen, BIO *out, char **rcpts,
	int num_rcpts, int base64)
{
	int64_t ret = -1;
	unsigned char key[EVP_MAX_KEY_LENGTH + EVP_MAX_MD_SIZE];
	int keylen, i;
	char *ciphertext = NULL;
	BIO *b64 = NULL;
	int64_t len, total_len = 0;
	
	OPENSSL_assert(in);
	OPENSSL_assert(inlen > 0);
	OPENSSL_assert(out);
	OPENSSL_assert(rcpts);
	OPENSSL_assert(num_rcpts > 0);
	
	len = sizeof("CPK EnvelopedData");
	if (BIO_puts(out, "CPK EnvelopedData\n") != len) {
		ERR_print_errors(bio_err);
		goto end;
	}
	total_len += len;
	
	keylen = EVP_CIPHER_key_length(default_cipher) +
		EVP_MD_size(default_md);
	RAND_bytes(key, keylen);
	
	for (i = 0; i < num_rcpts; i++) {
		if (!(ciphertext = cpktool_encrypt_text((char *)key, keylen, rcpts[i]))) {
			BIO_printf(bio_err, "%s: cpktool_encrypt_text() failed\n",
				prog);
			goto end;
		}
		len = strlen(rcpts[i]) + strlen(ciphertext) + strlen(":\n");
		if (BIO_printf(out, "%s:%s\n", rcpts[i], ciphertext) != len) {
			ERR_print_errors(bio_err);
			goto end;
		}
		total_len += len;
		
		OPENSSL_free(ciphertext);
		ciphertext = NULL;
	}
	
	if (BIO_puts(out, "\n") != 1) {
		ERR_print_errors(bio_err);
		goto end;
	}
	total_len += 1;
		
	if (base64) {
		if (BIO_puts(out, "base64\n") != sizeof("base64")) {
			ERR_print_errors(bio_err);
			goto end;
		}
		total_len += sizeof("base64");
		if (!(b64 = BIO_new(BIO_f_base64()))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!(out = BIO_push(b64, out))) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {
		if (BIO_puts(out, "none\n") != sizeof("none")) {
			ERR_print_errors(bio_err);
			goto end;
		}
		total_len += sizeof("none");
	}
	
	if ((len = sym_encrypt(in, inlen, out, key)) < 0) {
		BIO_printf(bio_err, "%s: encrypt data failed\n", prog);
		goto end;
	}
	total_len += len;
	ret = total_len;
end:
	if (ciphertext) OPENSSL_free(ciphertext);
	if (b64) BIO_free(b64);
	return ret;
}

static int envelope_decrypt(BIO *in, BIO *out, const char *pass)
{
	int ret = -1;
	char buffer[CPKTOOL_BUFSIZE];
	char *id;
	unsigned char *key = NULL;
	int keylen;
	int get_key = 0;
	BIO *b64 = NULL;
	EVP_PKEY *pkey = NULL;
	
	OPENSSL_assert(in);
	OPENSSL_assert(out);
	OPENSSL_assert(pass);
	
	if (BIO_gets(in, buffer, sizeof(buffer)) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (strncmp(buffer, "CPK EnvelopedData\n", strlen("CPK EnvelopedData\n"))) {
		BIO_printf(bio_err, "%s: format error: %s\n", prog, buffer);
		goto end;
	}
	
	if (!(id = cpktool_get_identity())) {
		BIO_printf(bio_err, "%s: load id failed\n", prog);
		goto end;
	}
	if (!(pkey = load_key_file(path_decryptkey, pass))) {
		BIO_printf(bio_err, "%s: shit\n", prog);
		goto end;
	}
	
	for (;;) {
		char *p;
	
		if (BIO_gets(in, buffer, sizeof(buffer)) <= 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
		
		if (!strncmp(buffer, "\n", 1))
			break;
		
		if (!(p = strchr(buffer, ':'))) {
			BIO_printf(bio_err, "%s: format error: %s\n", prog,
				buffer);
			goto end;
		}
		*p = 0;
		
		
		
		if (strcmp(buffer, id)) {
			BIO_printf(bio_err, "%s: found recipient id %s\n",
				prog, buffer);
			continue;
		}
		
		BIO_printf(bio_err, "%s: info: recipient %s found\n",
			prog, buffer);

		p++;
		
		if (!(key = (unsigned char *)cpktool_decrypt_text(p, &keylen,
			pass))) {
			BIO_printf(bio_err, "%s: decrypt key failed\n", prog);
			goto end;
		}
		
		if (keylen < EVP_CIPHER_key_length(default_cipher) +
			EVP_MD_size(default_md)) {
			BIO_printf(bio_err,
				"%s: symmetric key length = %d invalid\n",
				prog, keylen);
			goto end;
		}
		
		get_key = 1;
	}
	
	if (!get_key) {
		BIO_printf(bio_err, "%s: ciphertext not for me\n", prog);
		goto end;
	}
	
	if (BIO_gets(in, buffer, sizeof(buffer)) <= 0) {
		ERR_print_errors(bio_err);
		goto end;
	}	

	if (strcmp(buffer, "base64\n") == 0) {
		if (!(b64 = BIO_new(BIO_f_base64()))) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (!(in = BIO_push(b64, in))) {
			ERR_print_errors(bio_err);
			goto end;
		}

	} else if (strcmp(buffer, "none\n") != 0) {
		BIO_printf(bio_err, "%s: invalid encoding algor %s\n", prog, 
			buffer);
		goto end;
	}

	if (sym_decrypt(in, out, key) < 0) {
		BIO_printf(bio_err, "%s: symmetric decrypt failed\n", prog);
		goto end;
	}
	
	ret = 0;
end:
	if (key) OPENSSL_free(key);
	if (b64) BIO_free(b64);
	return ret;
}

static int get_file_stub(const char *file, char **type, unsigned char **stub,
	int *len)
{
	const char *p;
	char suffix[8];
	int i;
	
	if (!(p = strrchr(file, '.')))
		return -1;
	
	if (!(++p))
		return -1;
	
	if (strlen(p) + 1 > sizeof(suffix))
		return -1;
	
	strcpy(suffix, p);
	
	for (i = 0; i < strlen(suffix); i++)
		suffix[i] = (char)tolower(suffix[i]);
		
	if (!strcmp(suffix, "doc")) {
		*type = "doc";
		*stub = stub_doc;
		*len = sizeof(stub_doc);

	} else if (!strcmp(suffix, "ppt")) {
		*type = "ppt";
		*stub = stub_ppt;
		*len = sizeof(stub_ppt);	
	
	} else if (!strcmp(suffix, "xls")) {
		*type = "xls";
		*stub = stub_xls;
		*len = sizeof(stub_xls);	
	
	} else if (!strcmp(suffix, "rtf")) {
		*type = "rtf";
		*stub = stub_rtf;
		*len = sizeof(stub_rtf);	
	
	} else if (!strcmp(suffix, "jpg") || 
		   !strcmp(suffix, "jpeg")) {
		*type = "jpeg";
		*stub = stub_jpg;
		*len = sizeof(stub_jpg);	
	
	} else if (!strcmp(suffix, "png")) {
		*type = "png";
		*stub = stub_png;
		*len = sizeof(stub_png);	
		
	} else if (!strcmp(suffix, "pdf")) {
		*type = "pdf";
		*stub = stub_pdf;
		*len = sizeof(stub_pdf);	
	} else if (!strcmp(suffix, "docx")) {
		*type = "docx";
		*stub = stub_docx;
		*len = sizeof(stub_docx);	
		
	} else if (!strcmp(suffix, "pptx")) {
		*type = "pptx";
		*stub = stub_pptx;
		*len = sizeof(stub_pptx);	
	} else {
		*type = NULL;
		*stub = NULL;
		*len = 0;
		return -1;
	}
	
	return 0;
}

static off_t get_payload_pos(const char *file)
{
	FILE *fp = NULL;
	off_t file_size;
	long len;
	char final_block[32];
	struct stat st;
	
	if (stat(file, &st) < 0) {
		BIO_printf(bio_err, "%s: stat() failed\n", prog);
		goto end;
	}
	file_size = st.st_size;
	
	if (!(fp = fopen(file, "r"))) {
		BIO_printf(bio_err, "%s: open file %s failed\n", prog, file);
		goto end;
	}
	if (fseek(fp, -sizeof(final_block), SEEK_END) < 0) {
		BIO_printf(bio_err, "%s: shit\n", prog);
		goto end;
	}
	if (fread(final_block, 1, sizeof(final_block), fp) 
		!= sizeof(final_block)) {
		BIO_printf(bio_err, "%s: shit\n", prog);
		goto end;
	}
	if (memcmp(final_block, "CPK EOF ", sizeof("CPK EOF"))) {
		BIO_printf(bio_err, "%s: invalid format\n", prog);
		goto end;
	}
	if ((len = atol(final_block + sizeof("CPK EOF"))) <= 0) {
		BIO_printf(bio_err, "%s: invalid format\n", prog);
		goto end;
	}
	
	
	return file_size - len - sizeof(final_block);
	
end:	
	return -1;
}
