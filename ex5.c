#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char BYTE;
typedef enum { false, true } bool;

void print_hexa(BYTE *print, int size, char * text){
    printf("%s\n",text);
    for(int i=0;i<size;i++){
        printf("%x ",print[i]);
    }
    printf("\n");
}


void print_BN(BIGNUM *bn, BYTE *text){
    int size;
    BYTE *buffer;

    buffer = (BYTE*)malloc(sizeof(BYTE)*BN_num_bytes(bn));
    BN_bn2bin(bn,buffer);
    print_hexa(buffer,BN_num_bytes(bn),text);
    
   free(buffer);
}


BIGNUM* getSignature(BIGNUM *sgn,  BYTE *keyfile){
    
    BIGNUM *msg, *n, *k, *inv;
    BN_CTX *ctx;
    FILE *keyfp, *kfile;
    RSA *rsa_key;
    BYTE kbt[64];

    //citim k din fisier
    kfile = fopen("k.file","rb");
    fread(kbt,1,64,kfile);
 
    //initializam contextul si bn
    ctx = BN_CTX_new();
    k = BN_new();
    n = BN_new();
    msg = BN_new();
    inv = BN_new();

    BN_bin2bn(kbt,64,k);
    
    //citim cheia si extragem n ul
    keyfp = fopen(keyfile, "rb");
    rsa_key = PEM_read_RSAPrivateKey(keyfp,NULL,NULL,NULL);

    if (rsa_key == NULL){
        printf("null rsa key\n");
    }
    RSA_get0_key(rsa_key,&n, NULL, NULL);
   
    // calculam inversul lui k
    BN_mod_inverse(inv,k,n,ctx);

    //inmultim mesajul semnat cu inversul lui k mod n
    
    if (BN_mod_mul(msg,sgn,inv,n,ctx) == 0){
        printf("eroare la inmultire");
        return false;
    };

    //eliberam resursele
    BN_free(inv);
    BN_free(n);
    BN_free(k);

    BN_CTX_free(ctx);

    fclose(keyfp);
    fclose(kfile);

    return msg;

}

bool verifyBlidSignature (char* inputfile, char* keyfile, char* signaturefile) {
    
    SHA512_CTX sha512_ctx;
    FILE *infp, *sigfp, *keyfp;
    int file_size;
    RSA *rsa_key;
    BYTE *inTxt, hashTxt[64], *sigBytes, extractedHash[64], key[64];
    BIGNUM *msg, *signature, *e, *n, *hash;
    BN_CTX *ctx;

    ctx =BN_CTX_new();

     //deschidem fisierul 
    infp = fopen(inputfile, "rb");
    if (infp == NULL){
        printf("eroare la deschiderea fisierului\n");
        return false;
    }

    //aflam lungimea inputului
    fseek(infp,0,SEEK_END);
    file_size = ftell(infp);
    fseek(infp,0,SEEK_SET);
   
    //citim continutul fisierului 
    inTxt = (BYTE*)malloc(sizeof(BYTE)*file_size);
    fread(inTxt,file_size,1,infp);
    
    //creare hash text
    SHA512_Init(&sha512_ctx);
    SHA512_Update(&sha512_ctx,inTxt,file_size);
    SHA512_Final(hashTxt,&sha512_ctx);
    
    //deschidem fisierul semnat
    sigfp = fopen(signaturefile, "rb");

    //aflam lungimea inputului
    fseek(sigfp,0,SEEK_END);
    file_size = ftell(sigfp);
    fseek(sigfp,0,SEEK_SET);

    //citim continutul fisierului 
    sigBytes = (BYTE*)malloc(sizeof(BYTE)*file_size);
    fread(sigBytes,file_size,1,sigfp);

    signature = BN_new();
    BN_bin2bn(sigBytes,file_size,signature);
    
    //obtinem mesajul "deblurat"
    msg = getSignature(signature,keyfile);

    //citim cheia 
    keyfp = fopen(keyfile,"rb");
    rsa_key = PEM_read_RSAPrivateKey(keyfp,NULL,NULL,NULL);

    //extragem n si e din cheia
    RSA_get0_key(rsa_key,&n,&e,NULL);
    hash = BN_new();
    
    //extragem hashul
    BN_mod_exp(hash,msg,e,n,ctx);

    //convertim hashul extras din bn in bytes
    BN_bn2bin(hash,extractedHash);

    //comparam cele doua hashuri 
    for (int i=0;i<64;i++){
        if(extractedHash[i] != hashTxt[i]){
            return false;
        }
    }
    print_hexa(extractedHash,64,"extacted hashhh");
    print_hexa(hashTxt,64,"computeed hashh");

    //eliberam resursele
    BN_free(msg);
    BN_free(signature);
    BN_free(hash);
    BN_CTX_free(ctx);

    free(inTxt);
    free(sigBytes);

    fclose(infp);
    fclose(sigfp);
    fclose(keyfp);

    return true;

}

BIGNUM *signBlindMessage(BIGNUM *blind, BYTE *keyfile){

    BIGNUM *signed_msg, *n, *d, *e;
    BN_CTX *ctx;
    FILE *keyfp;
    RSA *rsa_key;

    ctx = BN_CTX_new();
    e = BN_new();
    n = BN_new();
    d = BN_new();
    signed_msg = BN_new();
  
    keyfp = fopen(keyfile, "rb");
    rsa_key = PEM_read_RSAPrivateKey(keyfp,NULL,NULL,NULL);

    RSA_get0_key(rsa_key,&n, &e, &d);
    
    //ridicam la puterea d mesajul "blurat" (semnam cu cheia privata)
    if ( BN_mod_exp(signed_msg,blind,d,n,ctx) == 0){
        printf("eroare la generarea semnaturii");
    };

    //eliberam resursele
    BN_free(d);
    BN_free(e);
    BN_free(n);
    BN_CTX_free(ctx);
    fclose(keyfp);

    return signed_msg;

}

BIGNUM* createBlindMessage( BYTE *inputfile, BYTE *keyfile, BYTE *passphrase, int ct){

    SHA512_CTX sha512_ctx;
    RSA *rsa_key;
    FILE *infp, *pubkey, *outfile;
    BYTE *inTxt, *mix;
    BYTE hashTxt[64], nonce[16], H1[64], H2[64];
    BIGNUM *k, *e, *n, *blind, *txt, *out;
    BN_CTX *ctx;
    int file_size, pass_size, shaSize;

    ctx = BN_CTX_new();

    //deschidem fisierul 
    infp = fopen(inputfile, "rb");

    //aflam lungimea inputului
    fseek(infp,0,SEEK_END);
    file_size = ftell(infp);
    fseek(infp,0,SEEK_SET);
    
    //citim continutul fisierului 
    inTxt = (BYTE*)malloc(sizeof(BYTE)*file_size);
    fread(inTxt,file_size,1,infp);
    
    //creare hash text
    SHA512_Init(&sha512_ctx);
    SHA512_Update(&sha512_ctx,inTxt,file_size);
    SHA512_Final(hashTxt,&sha512_ctx);
 
    //creare factor de orbire

    pass_size = strlen(passphrase);

    //generam nonce ul
    RAND_bytes(nonce,16);

    //concatenam parola cu nonce ul
    mix = (BYTE*)malloc(sizeof(BYTE)*(64+pass_size));//64 lungimea hashului
    memcpy(mix,passphrase,pass_size);
    memcpy(mix+pass_size, nonce, 16);

    //calculam U1
    shaSize = 16 + pass_size;
    SHA512_Update(&sha512_ctx, mix, shaSize);
    SHA512_Final(H1,&sha512_ctx);

    shaSize = 64 + pass_size;

    //calculam iterativ k 

    for (int i=0;i<ct-1;i++){
         
         SHA512_Update(&sha512_ctx, H1, shaSize);
         SHA512_Final(H2,&sha512_ctx);

         for(int j=0;j<64;j++){
             H1[j] = H1[j] ^ H2[j];
         }
    }

    //salvam k in fisier 
    outfile = fopen("k.file","wb+");
    fwrite(H1,64,1,outfile);
  
    
    k = BN_new();
    blind = BN_new();
    n = BN_new();
    txt = BN_new();
    out = BN_new();
    e = BN_new();

    //convertim k din BYTES in bn
    BN_bin2bn(H1,64,k);

    // convertim hashul textului in bn
    BN_bin2bn(hashTxt,64,txt);

    //citire cheie publica
    pubkey = fopen(keyfile,"rb");

    if ( pubkey == NULL){
        printf("open failed");
    }

    rsa_key = PEM_read_RSAPrivateKey(pubkey,NULL,NULL,NULL);

    if (rsa_key == NULL){
        printf("null\n");
    }

    //extragem e si n
    RSA_get0_key(rsa_key,&n,&e,NULL);

    //generare mesaj "blind"
  
    if ( BN_mod_exp(blind,k,e,n,ctx) == 0){
        printf("eroare la calcularea k\n");
    };

    if ( BN_mod_mul(out,blind,txt,n,ctx) == 0){
        printf("eroare la calcularea mesajului blind\n");
    }

    //eliberam resursele
    BN_free(k);
    BN_free(e);
    BN_free(n);
    BN_free(txt);
    BN_CTX_free(ctx);

    free(mix);
    
    fclose(pubkey);
    fclose(infp);
    fclose(outfile);

    //returnam mesajul "blind"
    return out;

}

void createBlindSignature( BYTE *inputfile, BYTE *keyfile, BYTE *passphrase, int n, BYTE *signaturefile){

    BIGNUM *blind, *signed_msg, *original_msg;
    FILE *sigfp;
    BYTE *signedmsg;
    
    //calculare mesaj "blind"
    blind = createBlindMessage(inputfile, keyfile, passphrase, n);

    //semnarea mesajului 
    signed_msg = signBlindMessage(blind, keyfile);

    //scrierea mesajului semnat in fisier
    signedmsg = (BYTE*)malloc(sizeof(BYTE)*BN_num_bytes(signed_msg));
    BN_bn2bin(signed_msg,signedmsg);

    sigfp = fopen(signaturefile, "wb+");
    if ( sigfp == NULL){
        printf("eroare la deschiderea fisierului\n");
        return -1;
    }

    fwrite(signedmsg, BN_num_bytes(signed_msg), 1, sigfp);
    fclose(sigfp);
    free(signedmsg);

    //verificarea semnaturii
    if(verifyBlidSignature(inputfile, keyfile, signaturefile) == true){
        printf("signature succesfully checked\n");
    }
    else{
        printf("error at checking signature\n");
    }

}


int main(){
  
    createBlindSignature("infile.file","private.key","passphrase",10,"sig.file");
    return 1;
}