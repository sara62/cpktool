#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cpktool.h"

int main(void)
{
	int rv;
	char *id = "identity";
	char *param_file = "cpk_param_file";
	char *signkey_file = "cpk_signkey_file";
	char *cryptkey_file = "cpk_decryptkey_file";
	char *password = "password";
	char *text = "hello worldlsdkfjlsdkjflskdjflksdjflksjdflksjdflksdjf;akdfj;aksdfj;laksdjf;lksdjf;lksdjfl;ksjdflklskdjflskdjf";
	char *signature = NULL;
	char *ciphertext = NULL;
	char *plaintext = NULL;
	int len;
	char *rcpts[] = {
		"identity",
		"alice",
		"bob",
	};
	int num_rcpts = sizeof(rcpts)/sizeof(rcpts[0]);

	printf("    test cpktool_init()                           ");
	rv = cpktool_init(NULL, NULL, NULL, NULL);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_setup()                          ");
	rv = cpktool_setup("http://www.opencpk.org");
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_export_params()                  ");
	rv = cpktool_export_params(param_file);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_import_params()                  ");
	rv = cpktool_import_params(param_file);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	//printf("    test cpktool_print_params()                   ");
	//rv = cpktool_print_params(param_file);
	//printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_genkey()                         ");
	rv = cpktool_genkey(id, signkey_file, password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	printf("test cpktool_genkey ");
	rv = cpktool_genkey(id, cryptkey_file, password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_set_identity()                   ");
	rv = cpktool_set_identity(id);
	printf("%s\n", rv == 0 ? "ok" : "failed");

	printf("    test cpktool_import_sign_key()                ");
	rv = cpktool_import_sign_key(signkey_file, password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_change_sign_password()           ");
	rv = cpktool_change_sign_password(password, password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_import_decrypt_key()             ");
	rv = cpktool_import_decrypt_key(cryptkey_file, password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_change_decrypt_password()        ");
	rv = cpktool_change_decrypt_password(password, password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_sign_text()                      ");
	signature = cpktool_sign_text(text, -1, password);
	printf("%s\n", signature ? "ok" : "failed");
		
	printf("    test cpktool_verify_text()                    ");
	rv = cpktool_verify_text(text, -1, signature, id);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_sign_file()                      ");
	signature = cpktool_sign_file(param_file, password);
	printf("%s\n", signature ? "ok" : "failed");

	printf("    test cpktool_verify_file()                    ");
	rv = cpktool_verify_file(param_file, signature, id);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_encrypt_text()                   ");
	ciphertext = cpktool_encrypt_text(text, -1, id);
	printf("%s\n", ciphertext ? "ok" : "failed");
	
	printf("    test cpktool_decrypt_text()                   ");
	plaintext = cpktool_decrypt_text(ciphertext, &len, password);
	if (plaintext && strcmp(plaintext, text) == 0)
		printf("ok\n");
	else	printf("failed\n");

	printf("clen = %d\n", strlen(ciphertext));

	printf("    test cpktool_decrypt_text() with error input  ");
	plaintext = cpktool_decrypt_text(ciphertext+1, &len, password);
	if (plaintext && strcmp(plaintext, text) == 0)
		printf("ok\n");
	else    printf("decrypt failed\n");
	
	printf("    test cpktool_envelope_encrypt_text()          ");
	ciphertext = cpktool_envelope_encrypt_text(text, -1, rcpts, num_rcpts);
	printf("%s\n", ciphertext ? "ok" : "failed");
	
	printf("    test cpktool_envelope_decrypt_text()          ");
	plaintext = cpktool_envelope_decrypt_text(ciphertext, -1, &len, password);
	if (plaintext && strcmp(plaintext, text) == 0)
		printf("ok\n");
	else	printf("failed\n");
	
	if (system("echo \"hello world slfja;lskdjf;alskdjf;\na;lskjf;lkajsdf\" > test.txt") < 0) {
		printf("shit\n");
	}

	printf("    test cpktool_envelope_encrypt_file() binary   ");
	rv = cpktool_envelope_encrypt_file("test.txt", "test.txt.cpk", rcpts, num_rcpts, 0);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_envelope_decrypt_file() binary   ");
	rv = cpktool_envelope_decrypt_file("test.txt.cpk", "test.2", password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	if (system("diff test.txt test.2") < 0) {
		printf("shit\n");
	}

	printf("    test cpktool_envelope_encrypt_file() base64   ");
	rv = cpktool_envelope_encrypt_file("test.txt", "test.txt.cpk", rcpts, num_rcpts, 1);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	printf("    test cpktool_envelope_decrypt_file() base64   ");
	rv = cpktool_envelope_decrypt_file("test.txt.cpk", "test.2", password);
	printf("%s\n", rv == 0 ? "ok" : "failed");
	
	if (system("diff test.txt test.2") < 0) {
		printf("shit\n");
	}
	
	cpktool_exit();

	return 0;
}

