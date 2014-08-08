/* cpktool header file
 * Copyright (C) 2009 - 2011 Zhi Guan <guan@pku.edu.cn>
 */

#ifndef HEADER_CPKTOOL_H
#define HEADER_CPKTOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define CPKTOOL_VERSION	"1.2"

/*
 * Example Values:
 *
 * user_home = 
 *	"/home/username" in UNIX
 *	"/sdcard" in Android
 *	"C:\Documents and Settings\username" in Windows XP
 *	"C:\Users\username" in Windows Vista/7
 * prog_home = ".cpk";
 * prog_name = "cpk"
 */
int   cpktool_init(const char *user_home, const char *prog_home, char *prog_name, FILE *err_fp);
void  cpktool_exit(void);
int   cpktool_setup(const char *domainid);
int   cpktool_import_master(const char *file);
int   cpktool_export_master(const char *file);
int   cpktool_print_master(const char *file);
int   cpktool_import_params(const char *file);
int   cpktool_export_params(const char *file);
int   cpktool_print_params(const char *file);
int   cpktool_genkey(const char *id, const char *file, const char *pass);
char *cpktool_gen_key(const char *id, const char *pass);
int   cpktool_print_key(const char *file, const char *pass);
int   cpktool_set_identity(const char *id);
char *cpktool_get_identity(void);
int   cpktool_import_sign_key(const char *file, const char *pass);
int   cpktool_change_sign_password(const char *old_pass, const char *new_pass);
int   cpktool_delete_sign_key(const char *pass);
int   cpktool_import_decrypt_key(const char *file, const char *pass);
int   cpktool_change_decrypt_password(const char *old_pass, const char *new_pass);
int   cpktool_delete_decrypt_key(const char *pass);
char *cpktool_sign_text(const char *text, int textlen, const char *pass);
int   cpktool_verify_text(const char *text, int textlen, const char *signature, const char *signer);
char *cpktool_sign_file(const char *file, const char *pass);
int   cpktool_batch_sign_file(const char *file, const char *pass);
int   cpktool_verify_file(const char *file, const char *signature, const char *signer);
char *cpktool_encrypt_text(const char *text, int textlen, const char *id);
char *cpktool_decrypt_text(const char *text, int *outlen, const char *pass);
char *cpktool_envelope_encrypt_text(const char *text, int textlen, char **rcpts, int num_rcpts);
char *cpktool_envelope_decrypt_text(const char *text, int textlen, int *outlen, const char *pass);
int   cpktool_envelope_encrypt_file(const char *infile, const char *outfile, char **rcpts, int num_rcpts, int base64);
int   cpktool_envelope_decrypt_file(const char *infile, const char *outfile, const char *pass);
int   cpktool_format_preserve_sign_file(const char *infile, const char *outfile, const char *pass);
int   cpktool_format_preserve_verify_file(const char *file);
int   cpktool_format_preserve_encrypt_file(const char *infile, const char *outfile, char **rcpts, int num_rcpts, int base64);
int   cpktool_format_preserve_decrypt_file(const char *infile, const char *outfile, const char *pass);
int   cpktool_add_policy_entry(const char *policy, const char *comment, int flags);
int   cpktool_remove_policy_entry(int entry);
int   cpktool_get_policy_entry_init(void);
int   cpktool_get_policy_entry_next(char **policy, char **comment, int *flags);
int   cpktool_get_policy_entry_final(void);
int   cpktool_validate_identity(const char *id);
int   cpktool_revoke_identity(const char *id, int reason);
int   cpktool_get_identity_state(const char *id);
int   cpktool_get_identity_metadata(const char *id, void *meta);
int   cpktool_get_identity_init(const char *template, int flags);
int   cpktool_get_identity_next();
int   cpktool_get_identity_exit();
char *cpktool_get_current_identity(const char *id);
int   cpktool_import_revocation_list(const char *file);
int   cpktool_export_revocation_list(const char *file);
int   cpktool_print_revocation_list(void);	


#ifdef __cplusplus
}
#endif
#endif
