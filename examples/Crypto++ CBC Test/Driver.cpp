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

std::streampos fileSize( const char* filePath ){

    std::streampos fsize = 0;
    std::ifstream file( filePath, std::ios::binary );

    fsize = file.tellg();
    file.seekg( 0, std::ios::end );
    fsize = file.tellg() - fsize;
    file.close();

    return fsize;
}

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    // string plain = "CBC Mode Test";
    string encoded;

    string file_out("");


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
            {"out", required_argument, 0, 'c'},
            {"help", no_argument, 0, 'i'},
            {"key", required_argument, 0, 'd'},
            {"iv", required_argument, 0, 'e'},
            {0, 0, 0, 0}
        };

#define HELP \
    printf("Usage: \n ./crypto_cbc_test [OPTIONS] \n"); \
    printf("    file:            file for doing encryption \n"); \
    printf("    action:          0: encryption, 1: decryption, 2: both Default 2 \n"); \
    printf("    out:             write out file, default no \n"); \
    printf("    key:             key in hex string, if it is not specified, automatically generate \n"); \
    printf("    iv:              Initialization vector, if it is not specified, automatically generate \n"); \
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
        case 'c':
            printf("[Debug] out: %s \n", optarg);
            file_out.append(optarg);
            break;
        case 'd':
            printf("[Debug] key: %s \n", optarg);
            for (int i = 0; i < 16; i++)
                key[i] = i;
            /*
            CryptoPP::ArraySink ar(key, sizeof(key));
            StringSource(new string(optarg), true, new CryptoPP::HexDecoder( ar ));
            */
            break;
        case 'e':
            printf("[Debug] iv: %s \n", optarg);
            for (int i = 0; i < 16; i++)
                iv[i] = i;

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

    std::ofstream outfile;


    if (file_out.length() > 0)
        outfile.open(file_out.c_str());

    if (action == 0)
        cout << "[Encryption]:  ";
    else if (action == 1)
        cout << "[Decryption]:  ";
    else if (action == 2)
        cout << "[Encryption|Decryption]:  ";



    cout  << file_path <<  "size: " << fileSize(file_path) << " (Bytes)" << endl;

    timeCounter tc(true);

    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);


    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);


    int count;
    int acc_count = 0;
    while ((count = infile.read(file_buff, 16).gcount()) > 0)
    {
        string cipher, recovered;

        std::string plain(file_buff, count);
        acc_count += count;

        if (action == 0 || action == 2)
        {

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
        }

        if (action == 1 || action == 2)
        {
            if (action == 1) // just do decryption
                cipher = plain;



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


        cout << "Size: " << acc_count << "," << count << ", " << cipher.size() << endl;

        if (outfile.is_open())
            if (action == 0)
                outfile.write(cipher.c_str(), cipher.size());
            else
                outfile.write(recovered.c_str(), recovered.size());

    }

    tc.Stop();
    printf("Elapsed: %s\n", tc.ToString().c_str());

    if (outfile.is_open())
        outfile.close();

    /*********************************\
    \*********************************/

    return 0;
}

