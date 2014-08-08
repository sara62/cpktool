#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifndef WIN32
#include <libgen.h>
#endif
#include <openssl/evp.h>
#include "cpktool.h"

enum cmd_type {
	cmd_setup = 1,
        cmd_import_master,
        cmd_export_master,
        cmd_print_master,
 	cmd_import_param,       
	cmd_export_param,
	cmd_print_param,
	cmd_genkey,
	cmd_print_key,
	cmd_set_identity,
	cmd_identity,
	cmd_import_sign_key,
        cmd_change_sign_password,
        cmd_delete_sign_key,
	cmd_import_decrypt_key,
	cmd_change_decrypt_password,
        cmd_delete_decrypt_key,
	cmd_sign,
	cmd_verify,
	cmd_format_preserve_sign,
	cmd_format_preserve_verify,
        cmd_envelope_encrypt,
        cmd_envelope_decrypt,
	cmd_envelope_encrypt_sign,
};

void print_help(enum cmd_type command, const char *prog)
{
	char *help[] = {
		"-help command",
		"-setup domainid",
                "-import-master [-in file]",
                "-export-master [-out file]",
                "-print-master [-in file]",
		"-import-param [-in file]",
		"-export-param [-out file]",
		"-print-param [-in file]",
		"-genkey identity [-out file] [-pass password]",
		"-print-key [-in file] [-pass password]",
		"-set-identity identity",
		"-identity",
		"-import-sign-key [-in file] [-pass password]",
                "-change-sign-password [-pass password] [-new-pass password]",
                "-delete-sign-key",
		"-import-decrypt-key [-in file] [-pass password]",
		"-change-decrypt-password [-pass password] [-new-pass password]",
                "-delete-decrypt-key",
		"-sign [-in file] [-out file] [-pass password]",
		"-verify signature -signer identity [-in file]",
		"-format-preserve-sign -in file [-out file] [-pass password]",
		"-format-preserve-verify [-in file]",
		"[-format-preserve] [-text] -encrypt [-to identity]* [-in file] [-out file]",
		"[-format-preserve] -decrypt [-in file] [-pass password] [-out file]",
	};
	
	assert(prog);
	assert(command > 0 && command < sizeof(help)/sizeof(help[0]));
	fprintf(stdout, "usage: %s %s\n", prog, help[command]);
}

void print_usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s command [options] ...\n", prog);
	fprintf(out, "\n");
	fprintf(out, "Commands:\n");
	fprintf(out, "  -help                       print system information\n");
	fprintf(out, "  -setup domainid             generate master secret and system parameters\n");
        fprintf(out, "  -import-master              import master secret to local storage\n");
        fprintf(out, "  -export-master              export master secret from local storage\n");
        fprintf(out, "  -print-master               print master secret\n");
	fprintf(out, "  -import-param               import public parameters to local storage\n");        
	fprintf(out, "  -export-param               export public parameters from local storage\n");
	fprintf(out, "  -print-param                print public parameters\n");
	fprintf(out, "  -genkey identity            generate a private key with an identity\n");
	fprintf(out, "  -print-key                  print private key\n");	
	fprintf(out, "  -set-identity identity      set identity\n");
	fprintf(out, "  -identity                   print identity\n");
	fprintf(out, "  -import-sign-key            import signing key\n");
        fprintf(out, "  -change-sign-password       change signing password\n");
        fprintf(out, "  -delete-sign-key            delete signing key\n");
	fprintf(out, "  -import-decrypt-key         import decryption key\n");
	fprintf(out, "  -change-decrypt-password    change decryption password\n");
        fprintf(out, "  -delete-decrypt-key         delete decryption key\n");
	fprintf(out, "  -sign                       generate standalone signature\n");
	fprintf(out, "  -verify signature           verify standalone signature\n");
	fprintf(out, "  -format-preserve-sign       attached sign\n");
	fprintf(out, "  -format-preserve-verify     verify attached signature\n");
	fprintf(out, "  -encrypt                    encrypt file to multiple recipients\n");
	fprintf(out, "  -decrypt                    decrypt file\n");
	fprintf(out, "\n");
	fprintf(out, "Options:\n");
        fprintf(out, "  -home path                  home path\n");
	fprintf(out, "  -signer identity            signer\n");
	fprintf(out, "  -to identity                recipient's identity, this option can be use multiple times\n");
	fprintf(out, "  -format-preserve            file format preserve cryptography operation\n");
	fprintf(out, "  -text                       text encode or decode\n");
	fprintf(out, "  -in file                    input file\n");
	fprintf(out, "  -out file                   output file\n");
	fprintf(out, "  -pass password              password\n");
	fprintf(out, "  -new-pass password          new password\n");
	fprintf(out, "  -verbose                    verbose\n");
	fprintf(out, "\n");
	fprintf(out, "Examples:\n");
	fprintf(out, "  %s -sign <document.txt >document.txt.sig\n", prog);
	fprintf(out, "  %s -verify $(cat document.txt.sig) <document.txt\n", prog);
	fprintf(out, "\n");
	fprintf(out, "Files:\n");
	fprintf(out, "  ~/.cpk/master_secret        system master secret\n");
	fprintf(out, "  ~/.cpk/public_params        system public parameters\n");
	fprintf(out, "  ~/.cpk/decrypt_key          decryption private key\n");
	fprintf(out, "  ~/.cpk/sign_key             signing private key\n");
	fprintf(out, "  ~/.cpk/identity             user's identifier\n");
	fprintf(out, "\n");
}

int main(int argc, char **argv)
{
	int r = -1;
	enum cmd_type command = 0;
        char *home = NULL;
#ifdef WIN32
	char *prog = "cpk";
#else
	char *prog = basename(argv[0]);
#endif
	char *infile = NULL;
	char *outfile = NULL;
	char *domainuri = NULL;
	char *identity = NULL;
	char *signer = NULL;
	char *signature = NULL;
	char *pass = NULL;
	char *newpass = NULL;
        char passbuf[64];
        char newpassbuf[64];
	int verbose = 0;
	int text = 0;
	int format_preserve = 0;
	int help = 0;
	char *rcpt[64];
	int num_rcpt = 0;
	int pass_required = 0;
	char buffer[1024];
	
	if (argc < 2) {
		fprintf(stdout, "%s toolkit %s (%s %s)\n", prog, CPKTOOL_VERSION, __DATE__, __TIME__);
		fprintf(stdout, "    %s -help for more inforamtion\n", prog);
		goto end;
	}
	
	argc--;
	argv++;
	while (argc >= 1) {

		if (!strcmp(*argv, "-setup")) {
			if (command) goto bad;
			command = cmd_setup;
			if (--argc < 1) {
				print_help(command, prog);
				goto end;
			}
			domainuri = *(++argv);
                
                } else if (!strcmp(*argv, "-import-master")) {
                        if (command) goto bad;
                        command = cmd_import_master;
                
                } else if (!strcmp(*argv, "-export-master")) {
                        if (command) goto bad;
                        command = cmd_export_master;

                } else if (!strcmp(*argv, "-print-master")) {
                        if (command) goto bad;
                        command = cmd_print_master;
                        
                } else if (!strcmp(*argv, "-import-param")) {
                        if (command) goto bad;
                        command = cmd_import_param;
		
		} else if (!strcmp(*argv, "-export-param")) {
			if (command) goto bad;
			command = cmd_export_param;
	
		} else if (!strcmp(*argv, "-print-param")) {
			if (command) goto bad;
			command = cmd_print_param;

		} else if (!strcmp(*argv, "-genkey")) {
			if (command) goto bad;
			command = cmd_genkey;	
			if (--argc < 1) {
				print_help(command, prog);
				goto bad;
			}
			identity = *(++argv);
			pass_required = 2;
			
		} else if (!strcmp(*argv, "-print-key")) {
			if (command) goto bad;
			command = cmd_print_key;
			pass_required = 1;			
	
		} else if (!strcmp(*argv, "-set-identity")) {
			if (command) goto bad;
			command = cmd_set_identity;
			if (--argc < 1) {
				print_help(command, prog);
				goto bad;
			}
			identity = *(++argv);
		
		} else if (!strcmp(*argv, "-identity")) {
			if (command) goto bad;
			command = cmd_identity;
			
		} else if (!strcmp(*argv, "-import-sign-key")) {
			if (command) goto bad;
			command = cmd_import_sign_key;
			pass_required = 1;
                        
		} else if (!strcmp(*argv, "-change-sign-password")) {
			if (command) goto bad;
			command = cmd_change_sign_password;
			pass_required = 3;
                
                } else if (!strcmp(*argv, "-delete-sign-key")) {
                        if (command) goto bad;
                        command = cmd_delete_sign_key;
                        pass_required = 1;
                        
		} else if (!strcmp(*argv, "-import-decrypt-key")) {
			if (command) goto bad;
			command = cmd_import_decrypt_key;
			pass_required = 1;

		} else if (!strcmp(*argv, "-change-decrypt-password")) {
			if (command) goto bad;
			command = cmd_change_decrypt_password;
			pass_required = 3;
                        
                } else if (!strcmp(*argv, "-delete-decrypt-key")) {
                        if (command) goto bad;
                        command = cmd_delete_decrypt_key;

		} else if (!strcmp(*argv, "-sign")) {
			if (!command) command = cmd_sign;
			else if (command == cmd_envelope_encrypt) command = cmd_envelope_encrypt_sign;
			else goto bad;
			pass_required = 1;
		
		} else if (!strcmp(*argv, "-verify")) {
			if (command) goto bad;
			command = cmd_verify;
			if (--argc < 1) {
				print_help(command, prog);
				goto bad;
			}
			signature = *(++argv);			
			
		} else if (!strcmp(*argv, "-encrypt")) {
			if (!command) command = cmd_envelope_encrypt;
			else if (command == cmd_sign) command = cmd_envelope_encrypt_sign;
			else goto bad;
		
		} else if (!strcmp(*argv, "-decrypt")) {
			if (command) goto bad;
			command = cmd_envelope_decrypt;
			pass_required = 1;
                        
                } else if (!strcmp(*argv, "-home")) {
                        if (--argc < 1) goto bad;
                        home = *(++argv);
	
		} else if (!strcmp(*argv, "-signer")) {
			if (--argc < 1) goto bad;
			signer = *(++argv);
		
		} else if (!strcmp(*argv, "-to")) {
			if (--argc < 1) goto bad;
			rcpt[num_rcpt] = *(++argv);
			num_rcpt++;

		} else if (!strcmp(*argv, "-text")) {
			text = 1;
			
		} else if (!strcmp(*argv, "-format-preserve")) {
			format_preserve = 1;

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
		
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
			
		} else if (!strcmp(*argv, "-new-pass")) {
			if (--argc < 1) goto bad;
			newpass = *(++argv);

		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
		} else if (!strcmp(*argv, "-help")) {
			help = 1;
		}
		
		argc--;
		argv++;
	}
	
	
	if (help) {
		if (command)
			print_help(command, prog);
		else	
			print_usage(stdout, prog);
		
		goto end;
	}
	
	if (pass_required == 1 && !pass) {
		if (EVP_read_pw_string(buffer, sizeof(buffer), "Enter Password: ", 0))
			goto end;
		pass = buffer;
	}
	if (pass_required == 2 && !pass) {
		if (EVP_read_pw_string(buffer, sizeof(buffer), "Enter Password: ", 1))
			goto end;
		pass = buffer;
	}
	if (pass_required == 3 && !pass) {
		if (EVP_read_pw_string(passbuf, sizeof(passbuf), "Enter Old Password: ", 0))
			goto end;
                pass = passbuf;
                if (cpktool_change_sign_password(pass, pass) < 0) {
                        goto end;
                }
	}
	if (pass_required ==3 && !newpass) {
		if (EVP_read_pw_string(newpassbuf, sizeof(newpassbuf), "Enter New Password: ", 1))
			goto end;
                newpass = newpassbuf;
	}

	if (cpktool_init(NULL, home, prog, stderr) < 0) {
		goto end;
	}

	switch (command) {
	case cmd_setup:
		r = cpktool_setup(domainuri);
		break;
        case cmd_import_master:
                r = cpktool_import_master(infile);
                break;
        case cmd_export_master:
                r = cpktool_export_master(outfile);
                break;
        case cmd_print_master:
                r = cpktool_print_master(infile);
                break;
	case cmd_import_param:
		r = cpktool_import_params(infile);
		break;
	case cmd_export_param:
		r = cpktool_export_params(outfile);
		break;
	case cmd_print_param:
		r = cpktool_print_params(infile);
		break;
	case cmd_genkey:
		r = cpktool_genkey(identity, outfile, pass);
		break;
	case cmd_print_key:
		r = cpktool_print_key(infile, pass);
		break;
	case cmd_set_identity: 
		r = cpktool_set_identity(identity);
		break;
	case cmd_identity:
		printf("%s\n", cpktool_get_identity());
		break;
	case cmd_import_sign_key:
		r = cpktool_import_sign_key(infile, pass);
		break;
	case cmd_change_sign_password:
		r = cpktool_change_sign_password(pass, newpass);
		break;
        case cmd_delete_sign_key:
                r = cpktool_delete_sign_key(pass);
                break;
        case cmd_import_decrypt_key:
		r = cpktool_import_decrypt_key(infile, pass);
		break;
	case cmd_change_decrypt_password:
		r = cpktool_change_decrypt_password(pass, newpass);
		break;
        case cmd_delete_decrypt_key:
                r = cpktool_delete_decrypt_key(pass);
                break;
	case cmd_format_preserve_sign:
		if (!infile) {
			fprintf(stderr, "%s: option -in is required by -format-preserve -sign",
				prog);
			goto end;
		}
		r = cpktool_format_preserve_sign_file(infile, outfile, pass);
		break;
        case cmd_sign:
//FIXME: the batch sign should be add to the CLI better
#if 1
		signature = cpktool_sign_file(infile, pass);
		if (!signature) {
			fprintf(stderr, "%s: sign failed\n", prog);
			goto end;
		}
		printf("%s\n", signature);
#endif
		//r = cpktool_batch_sign_file(infile, pass);
		//fprintf(stdout, "%s\n", signature);
		r = 0;
		break;
	case cmd_verify:
		if (format_preserve) {
			if (!infile) {
				fprintf(stderr, "%s: option -in is required by -format-preserve",
					prog);
				goto end;
			}
			r = cpktool_format_preserve_verify_file(infile);
		} else {
			if (!signer) {
				fprintf(stderr, "%s: option -signer required\n", prog);
				goto end;
			}
			r = cpktool_verify_file(infile, signature, signer);
			if (r == 0)
				fprintf(stdout, "success\n");
			else	fprintf(stdout, "failed\n");
		}
		break;
	case cmd_envelope_encrypt:
		if (format_preserve) {
			if (!infile) {
				fprintf(stderr, "%s: -format-preserve requires"
					" a specified input file\n", prog);
				goto end;
			}
			if (text) {
				fprintf(stderr, "%s: FIXME: can not read from a base64 BIO in deenvelop() "
					"maybe we need read the stub instead of seek\n", prog);
					goto end;
			}
			if (cpktool_format_preserve_encrypt_file(infile, outfile, rcpt, 
				num_rcpt, text) < 0) {
				fprintf(stderr, "%s: encrypt failed\n", prog);
				goto end;
			}
			r = 0;
		} else {
			r = cpktool_envelope_encrypt_file(infile, outfile, rcpt, num_rcpt, text);
		}
		break;
	case cmd_envelope_decrypt:
		if (format_preserve)
			r = cpktool_format_preserve_decrypt_file(infile, outfile, pass);
		else	r = cpktool_envelope_decrypt_file(infile, outfile, pass);
		break;
	default:
		fprintf(stderr, "%s: no command specified\n", prog);
		goto bad;
	}

	goto end;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);
end:

	cpktool_exit();
	return 0;
}


