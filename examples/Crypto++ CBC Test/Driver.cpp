// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::istream;
#include <fstream>

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"

#include "TimeCounter.h"

// some C library
#include <stdarg.h>
#include <getopt.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

   // string plain = "CBC Mode Test";
    string encoded, recovered;


    char file_path[256];
    int action;

    // default initialization
    strcpy(file_path, "test.dat");
    action = 2;
    while(1)
    {

        static struct option long_option[] =
        {
            {"file", required_argument, 0, 'a'},
            {"action", required_argument, 0, 'b'},
            {"help", required_argument, 0, 'i'},
            {0, 0, 0, 0}
        };

#define HELP \
    printf("Usage: \n ./crypto_cbc_test [OPTIONS] \n"); \
    printf("    file:            file for doing encryption \n"); \
    printf("    action:          0: encryption, 1: decryption, 2:both, Default 2 \n"); \
    printf("    help:            help  \n");


        int option_index = 0;
        int rc = getopt_long(argc, argv, "a:b:c:d:e:f:g:h:i", long_option, &option_index);

        if (rc == -1)
            break;

        switch(rc)
        {
        case 'a':
            printf("[Debug] file : %s \n", optarg);
            sprintf(file_path, optarg);
            break;
        case 'b':
            printf("[Debug] action: %s \n", optarg);
            action = atoi(optarg);
            break;
        case 'i':
            HELP
                    exit(1);
        default:
            printf("invalid option \n");
            exit(1);


        }


    }



    /*********************************\
    \*********************************/

    // Pretty print key
    encoded.clear();
    StringSource(key, sizeof(key), true,
                 new HexEncoder(
                     new StringSink(encoded)
                     ) // HexEncoder
                 ); // StringSource
    cout << "key: " << encoded << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, sizeof(iv), true,
                 new HexEncoder(
                     new StringSink(encoded)
                     ) // HexEncoder
                 ); // StringSource
    cout << "iv: " << encoded << endl;

    /*********************************\
    \*********************************/



    char file_buff[2*1024];

    std::ifstream infile(file_path, std::ifstream::binary);

    cout << "[Encryption|Decryption]:  " << file_path << endl;

    timeCounter tc(true);

    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);


    int count;
    int acc_count = 0;
    while ((count = infile.read(file_buff, 1024).gcount()) > 0)
    {
        string cipher;

        std::string plain(file_buff, count);
        acc_count += count;

        //cout << "data:" << plain << endl;
        try
        {

            // The StreamTransformationFilter removes
            //  padding as required.

            StringSource s(plain, true,
                           new StreamTransformationFilter(e,
                                                          new StringSink(cipher)
                                                          ) // StreamTransformationFilter
                           ); // StringSource

#if 0
            StreamTransformationFilter filter(e);
            filter.Put((const byte*)plain.data(), plain.size());
            filter.MessageEnd();

            const size_t ret = filter.MaxRetrievable();
            cipher.resize(ret);
            filter.Get((byte*)cipher.data(), cipher.size());
#endif
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            cerr << "ERRO 1" << endl;
            exit(1);
        }

        cout << "Size: " << acc_count << "," << count << ", " << cipher.size() << endl;

        /*********************************\
    \*********************************/
#if 0
        // Pretty print
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded)
                         ) // HexEncoder
                     ); // StringSource
        // cout << "cipher text: " << encoded << endl;
#endif

        /*********************************\
    \*********************************/

        try
        {

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource s(cipher, true,
                           new StreamTransformationFilter(d,
                                                          new StringSink(recovered)
                                                          ) // StreamTransformationFilter
                           ); // StringSource

#if 0
            StreamTransformationFilter filter(d);
            filter.Put((const byte*)cipher.data(), cipher.size());
            filter.MessageEnd();

            const size_t ret = filter.MaxRetrievable();
            recovered.resize(ret);
            filter.Get((byte*)recovered.data(), recovered.size());
#endif

           // cout << "recovered text: " << recovered << endl;
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            cout << "ERROR";
            exit(1);
        }


    }

    tc.Stop();
    printf("Elapsed: %s\n", tc.ToString().c_str());


    /*********************************\
    \*********************************/

    return 0;
}

