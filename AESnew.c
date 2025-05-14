#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma comment(lib, "bcrypt.lib")

#define MAX_INPUT 2048
#define KEY_SIZE 512
#define IV_SIZE 256

typedef struct _AES
{
    PBYTE pPlainText;  // base add of plain text
    DWORD dwPlainSize; // size of plain text

    PBYTE pCipherText;  // base address of encrypted data
    DWORD dwCipherSize; // size of enc data (after padding)

    PBYTE pKey; // 32 byte key
    PBYTE pIV;  // 16 byte iv
} AES, *PAES;

// Wrapper func for Install AesEncryptor that makes things easier

// the encryption implementation
BOOL InstallAesEncryption(PAES pAes)
{
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;

    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;

    DWORD cbKeyObject = 0; // nullto0
    PBYTE pbKeyObject = NULL;

    PBYTE pbCipherText = NULL;
    DWORD cbCipherText = 0; // nullto0

    NTSTATUS STATUS = 0;

    // Initializizng "hAlgorithm" as AES alg handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!]BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }
    // getting the size of the key object variable pbKeyObject.
    // This is used by the BCRyptGenerateSymmeetricKey function later

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Getting the size of block used in AES
    // since this is AES it must be 16 bytes.

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Checking if the block size is 16 bytes
    if (dwBlockSize != 16)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Setting block Cipher mode to CBC, This uses a 32 byte key and a 16 byte IV
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // generating the key from AES key "pAes->pKey", the output will be saved in pbKeyObject and will be of size cbKeyObject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, 32, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer
    // which is saved in cbCipherText
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIV, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // allocating enough memory for the output buffer, cbCipherText
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (pbCipherText == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Running BcryptEncrypt again with pbcipher text as the output buffer
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIV, 16, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

// clean-up
_EndOfFunc:
    if (hKeyHandle)
    {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbCipherText != NULL && bSTATE)
    {
        pAes->pCipherText = pbCipherText;
        pAes->dwCipherSize = cbCipherText;
    }
    return bSTATE;
}

// The decryption implementation
BOOL InstallAesDecryption(PAES pAes)
{
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;

    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;

    DWORD cbKeyObject = 0; // nullto0
    PBYTE pbKeyObject = NULL;

    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = 0; // nullto0

    NTSTATUS STATUS = 0;

    // initializing halgorithm as AES algorithm
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Getting the size of the key object variable pbKeyObject, This is used by the BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // checking if the block size is 16
    if (dwBlockSize != 16)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // setting block cipher mode to CBC, this uses a 32 byte key and 16 byte IV
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // generating key object from AES key "pAes->pKey".
    // output will be saved in pbkeyobject of size cbkeyobject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, 32, 0);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // running bcrypt first time with null output parameters to retrieve the size of the output buffer
    //  which is saved in cbPlaintext
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIV, 16, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Allocating enough memory for the output buffer, cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL)
    {
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

    // Running Bcryptdecrypt again with pbplaintext as the output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIV, 16, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS))
    {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE;
        goto _EndOfFunc;
    }

// clean-up
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE)
    {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}

BOOL SimpleEncryption(
    IN PVOID pPlainTextData,
    IN DWORD sPlainTextSize,
    IN PBYTE pKey,
    IN PBYTE pIV,
    OUT PVOID *pCipherTextData,
    OUT DWORD *sCipherTextSize)
{
    if (pPlainTextData == NULL || sPlainTextSize == 0 || pKey == NULL || pIV == NULL)
    {
        return FALSE;
    }
    // initializing the struct
    AES Aes = {
        .pKey = pKey,
        .pIV = pIV,
        .pPlainText = pPlainTextData,
        .dwPlainSize = sPlainTextSize};
    if (!InstallAesEncryption(&Aes))
    {
        return FALSE;
    }

    // saving output
    *pCipherTextData = Aes.pCipherText;
    *sCipherTextSize = Aes.dwCipherSize;

    return TRUE;
}

// Wrapper func for InstallAesDecryption that makes things easier
BOOL SimpleDecryption(
    IN PVOID pCipherTextData,
    IN DWORD sCipherTextSize,
    IN PBYTE pKey,
    IN PBYTE pIv,
    OUT PVOID *pPlainTextData,
    OUT DWORD *sPlainTextSize)
{
    if (pCipherTextData == NULL || sCipherTextSize == 0 || pKey == NULL || pIv == NULL)
    {
        return FALSE;
    }

    // initializing the struct again
    AES Aes = {
        .pKey = pKey,
        .pIV = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize};

    if (!InstallAesDecryption(&Aes))
    {
        return FALSE;
    }

    // output
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size)
{

    printf("unsigned char %s[] = {", Name);

    for (int i = 0; i < Size; i++)
    {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1)
        {
            printf("0x%0.2X, ", Data[i]);
        }
        else
        {
            printf("0x%0.2X ", Data[i]);
        }
    }

    printf("};\n\n\n");
}

// generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize)
{
    for (int i = 0; i < sSize; i++)
    {
        pByte[i] = (BYTE)rand() % 0xFF;
    }
}

char *readlinedyncamic()
{
    size_t size = 64;
    size_t len = 0;
    char *buffer = malloc(size);
    if (!buffer)
        return NULL;

    int c;
    while ((c = getchar()) != '\n' && c != EOF)
    {
        if (len + 1 >= size)
        {
            size *= 2;
            char *temp = realloc(buffer, size);
            if (!temp)
            {
                free(buffer);
                return NULL;
            }
            buffer = temp;
        }
        buffer[len++] = (char)c;
    }

    buffer[len] = '\0';
    return buffer;
}

int main()
{

    char EncorDec;
    printf("enter e to encrypt d to decrypt: ");
    scanf(" %c", &EncorDec);
    getchar();
    EncorDec = tolower((unsigned char)EncorDec);

    if (EncorDec == 'e')
    {

        BYTE pKey[32];
        BYTE pIv[16];

        srand(time(NULL)); // the seed used to generate the key
        GenerateRandomBytes(pKey, 32);

        srand(time(NULL) ^ pKey[0]); // seed to generate IV
        GenerateRandomBytes(pIv, 16);

        PrintHexData("pKey", pKey, 32);
        PrintHexData("pIv", pIv, 16);

        printf("enter the text to encrypt: ");
        char *plainTextString = readlinedyncamic();
        if (plainTextString)
        {
            free(plainTextString);
        }
        else
        {
            printf("input error ormemory allocatiton failed. \n");
        }
        size_t plainTextSize = strlen(plainTextString);

        PVOID pCipherText = NULL;
        DWORD dwCipherSize = 0;

        // encrypting
        if (!SimpleEncryption((PVOID)plainTextString, strlen(plainTextString), pKey, pIv, &pCipherText, &dwCipherSize))
        {
            //free(plainTextString);
            return -1;
        }

        // print the encrypted buffer as a hex array
        PrintHexData("Ciphertext", pCipherText, dwCipherSize);

        // cleanup
        HeapFree(GetProcessHeap(), 0, pCipherText);
        system("PAUSE");
    }
    else if(EncorDec == 'd'){
        PVOID	pPlaintext  = NULL;
        DWORD	dwPlainSize = 0;

        char input[MAX_INPUT];
        unsigned char *CipherText = NULL;
        size_t ciphersize = 0;

        printf("enter the ciphered hex: ");
        fgets(input, MAX_INPUT, stdin);
        
        char *token = strtok(input, ",");
        while (token != NULL){
            unsigned int value;

            while (*token == ' ') token ++;

            if(sscanf(token, "%x", &value) == 1){
                unsigned char *temp = realloc(CipherText, ciphersize+1);
                if (!temp){
                    printf("memory realloc fail");
                    free(CipherText);
                    return 1;
                }
                CipherText = temp;
                CipherText[ciphersize++] = (unsigned char)value;
            }
            else{
                printf("invalid token: %s\n", token);
            }

            token = strtok(NULL, ",");
        }
        printf("ciphered hex size: %zu\n", ciphersize);
        printf("\n");

        char keyinput[KEY_SIZE];
        unsigned char *pKey = NULL;
        size_t keysize = 0;

        printf("enter the key hex: ");
        fgets(keyinput, KEY_SIZE, stdin);
        getchar();
        

        char *keytoken = strtok(keyinput, ",");
        while (keytoken != NULL) {
            unsigned int value;

            while (*keytoken == ' ') keytoken++;

            if (sscanf(keytoken, "%x", &value) == 1) {
                unsigned char *temp = realloc(pKey, keysize + 1);
                if (!temp) {
                    printf("memory realloc fail\n");
                    free(keytoken);
                    return 1;
                }
                pKey = temp;
                pKey[keysize++] = (unsigned char)value;
            } else {
                printf("invalid token: %s\n", keytoken);
            }

            keytoken = strtok(NULL, ",");
        }

        printf("ciphered key size: %zu\n", keysize);
        printf("\n");


        char ivinput[IV_SIZE];
        unsigned char *pIv = NULL;
        size_t ivsize = 0;

        printf("enter the iv hex: ");
        fgets(ivinput, IV_SIZE, stdin);
        getchar();

        char *ivtoken = strtok(ivinput, ",");
        while (ivtoken != NULL) {
            unsigned int value;

            while (*ivtoken == ' ') ivtoken++;

            if (sscanf(ivtoken, "%x", &value) == 1) {
                unsigned char *temp = realloc(pIv, ivsize + 1);
                if (!temp) {
                    printf("memory realloc fail\n");
                    free(pIv);
                    return 1;
                }
                pIv = temp;
                pIv[ivsize++] = (unsigned char)value;
            } else {
                printf("invalid token: %s\n", ivtoken);
            }

            ivtoken = strtok(NULL, ",");
        }

        printf("ciphered IV size: %zu\n", ivsize);
        printf("\n");



        if (!SimpleDecryption(CipherText, ciphersize, pKey, pIv, &pPlaintext, &dwPlainSize)) {
            return -1;
        }

        PrintHexData("PlainText", pPlaintext, dwPlainSize);

        printf("Data: %s \n", pPlaintext);
        printf("Press Enter to exit...");
        getchar();
        // Clean up
        HeapFree(GetProcessHeap(), 0, pPlaintext);
        system("PAUSE");
        //printf("Press Enter to exit...");
        //getchar();
    }
    return 0;
}