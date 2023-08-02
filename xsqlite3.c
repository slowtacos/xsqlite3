#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <stdbool.h>
#include "shell.h"
#include "util.h"

#define NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define A_SIZE crypto_aead_xchacha20poly1305_ietf_ABYTES
#define KEY_SIZE crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define CRYPTO_ENCRYPT crypto_aead_xchacha20poly1305_ietf_encrypt
#define CRYPTO_DECRYPT crypto_aead_xchacha20poly1305_ietf_decrypt

sqlite3 *db;
char *database_path;

unsigned char nonce[NONCE_SIZE];
unsigned char key[KEY_SIZE];

struct termios term;

void gen_nonce(void) {
  randombytes(nonce, NONCE_SIZE);
}

unsigned char *encrypt_database(unsigned long long *len) {
  sqlite3_int64 db_size = 0;
  unsigned char *db_ptr = sqlite3_serialize(db, "main", &db_size, 0);
  if (db_ptr == NULL)
    die("could not serialize database");

  unsigned char *out = emalloc(A_SIZE + db_size);

  CRYPTO_ENCRYPT(out, len, db_ptr, db_size, NULL, 0, NULL, nonce, key);
  sqlite3_free(db_ptr);
  return out;
}

void extract_nonce(FILE *f) {
  if (fread(nonce, NONCE_SIZE, 1, f) != 1)
    die("could not read nonce from '%s'", database_path);

  efseek(f, 0, SEEK_SET);
}

void extract_database(FILE *f) {
  efseek(f, NONCE_SIZE, SEEK_SET);

  long start, end, size;
  start = eftell(f);

  efseek(f, 0, SEEK_END);

  end = eftell(f);

  efseek(f, start, SEEK_SET);

  size = end - start;

  unsigned char encrypted[size];
  if (fread(encrypted, size, 1, f) != 1)
    die("could not read database from '%s'", database_path);

  unsigned long long decrypted_len;
  unsigned char decrypted[size];

  if (CRYPTO_DECRYPT(decrypted, &decrypted_len, NULL, encrypted, size, NULL, 0, nonce, key) == -1)
    die("decrypt failed");

  if (sqlite3_deserialize(db, "main", decrypted, decrypted_len, sizeof decrypted, 0) != SQLITE_OK)
    die("could not deserialize database");
}

void load_database(void) {
  FILE *database_file = efopen(database_path, "r");

  extract_nonce(database_file);
  extract_database(database_file);

  efclose(database_file);
}

void init_database(void) {
  if (sqlite3_open(":memory:", &db) != SQLITE_OK)
    die("could not initialize database");
}

void save_database(void) {
  size_t database_tmp_path_len = strlen(database_path) + 5;
  char database_tmp_path[database_tmp_path_len];
  snprintf(database_tmp_path, database_tmp_path_len, "%s.tmp", database_path);

  FILE *database_file = efopen(database_tmp_path, "w+");

  gen_nonce();

  if (fwrite(nonce, NONCE_SIZE, 1, database_file) != 1)
    die("could not write nonce to '%s'", database_path);

  unsigned long long encrypted_size;
  unsigned char* encrypted;
  encrypted = encrypt_database(&encrypted_size);

  if (fwrite(encrypted, encrypted_size, 1, database_file) != 1)
    die("could not write database to '%s'", database_path);

  free(encrypted);

  efclose(database_file);

  if (rename(database_tmp_path, database_path) != 0)
      die("could not rename back '%s' to '%s'", database_path, database_tmp_path);
}

void close_database(void) {
  if (sqlite3_close(db) != SQLITE_OK)
    die("sqlite3_close");
}

void hash_password(char *password, size_t password_len, unsigned char *out) {
  crypto_generichash(out, KEY_SIZE, (unsigned char*)password, password_len, NULL, 0);
}

void toggle_echo(void) {
  term.c_lflag ^= ECHO;
  tcsetattr(fileno(stdin), 0, &term);
}

char* readpassword(char *prompt) {
  char *password = NULL;
  size_t password_n = 0;
  ssize_t password_len = 0;

  toggle_echo();
  printf("%s", prompt);
  if ((password_len = getline(&password, &password_n, stdin)) == -1)
    die("getline:");
  printf("\n");
  toggle_echo();

  password[password_len - 1] = '\0';
  return password;
}

int main(int argc, char **argv) {

  int opt;
  FILE *keyfile;
  unsigned char keyfilebuf[KEY_SIZE] = {0};

  while ((opt = getopt(argc, argv, "f:hk:")) != -1) {
    switch(opt) {
      case 'h':
        printf("usage: %s [OPTIONS] -f [FILE]\n", argv[0]);
        puts("\t-f [FILE] database file");
        puts("\t-k [KEYFILE] xor master key with KEYFILE after hashing password");
        return 0;
      case 'f':
        database_path = optarg;
        break;
      case 'k':
        keyfile = efopen(optarg, "r");

        if (fread(keyfilebuf, KEY_SIZE, 1, keyfile) != 1)
          die("could not read keyfile, make sure the file size is at least %u", KEY_SIZE);

        break;
    }
  }

  if (!database_path) {
    fprintf(stderr, "no database file provided\n");
    fprintf(stderr, "%s -h for help\n", argv[0]);
    return 1;
  }

  tcgetattr(fileno(stdin), &term);

  if (sodium_init() == -1)
    die("sodium_init");

  char *password = readpassword("password: ");

  if (access(database_path, F_OK) != 0) {
    char *password_tmp = readpassword("confirm password: ");

    if (!(strcmp(password, password_tmp) == 0))
      die("passwords does not match");

    free(password_tmp);
  }

  hash_password(password, strlen(password), key);

  free(password);

  if (memcmp(keyfilebuf, (unsigned char[KEY_SIZE]){0}, KEY_SIZE) != 0) {
    for (unsigned long long i = 0; i < KEY_SIZE; i++)
      key[i] ^= keyfilebuf[i];
  }

  init_database();

  if (access(database_path, F_OK) == 0)
    load_database();

  shell(db);

  save_database();

  close_database();

}
