#!/usr/bin/env python

import binascii
import sys
from sys import stdin
import hashlib
import os
import argparse
import base64
import random
from gmpy2 import *
import timeit

def genfile(base_contents1,base_contents2,outname):
    if outname is None:
        outname='certificate'
    with open('./gen_certs/{}1.cer'.format(outname),'wb') as outfile1:
        outfile1.write(base_contents1)
    with open('./gen_certs/{}2.cer'.format(outname),'wb') as outfile2:
        outfile2.write(base_contents2)
    os.system('openssl x509 -in ./gen_certs/{}1.cer -inform DER -out ./gen_certs/{}1.pem'.format(outname,outname))
    os.system('openssl x509 -in ./gen_certs/{}2.cer -inform DER -out ./gen_certs/{}2.pem'.format(outname,outname))


def modify_contents(file_contents, start, end, name):
    base_len=end-start
    print ('----------\nyou chose to modify {},with actual value"{}" you must enter a length of {}\n new string:'.format(name,file_contents[start:end],base_len))

    data = stdin.readline()
    data=data.strip()
    if len(data) != base_len :
        print 'wrong length entered, quitting modification'
    else :
        print data
        print len(data)
        file_contents=file_contents[0:start]+data+file_contents[end:]

    return file_contents




def modify_parameters_menu(file_contents, mybool):
    menu = {}
    print('[within options 1,2,3 and 4 of menu, we ask that total length of new value for the chosen parameter is equal to the length of the previous one (in order to not break whole structure). within option 5, you must provide a whole new asn1 starting part of the certificate(260 bytes length). If you don\'t want to modify any parameter, enter option 6]\n')
    menu['1']="modify common name"
    menu['2']="modify country"
    menu['3']="modify location"
    menu['4']="modify comment"
    menu['5']="modify total head of certificate"
    menu['6']="Exit parameters modifications"

    while True:
        if mybool is True:
            break
        options=menu.keys()
        options.sort()
        for entry in options:
            print entry, menu[entry]
        selection=raw_input("Please Select:")
        print('\n')
        if selection =='1':
            print "you selected option1"
            file_contents=modify_contents(file_contents,142,156,'common name')
        elif selection == '2':
            print "you selected option2"
            file_contents=modify_contents(file_contents,225,227,'country')
        elif selection == '3':
            print "you selected option3"
            file_contents=modify_contents(file_contents,205,214,'location')
        elif selection == '4':
            print "you selected option4"
            file_contents=modify_contents(file_contents,167,194,'comment')
        elif selection == '5':
            print "you selected option5"
            file_contents=modify_contents(file_contents,0,260,'all')
        elif selection == '6':
            break
        else:
            print "Unknown Option Selected!"
        print '\n--------\nnew option:'
    print '\nGenerating new cer template... [OK]\n\n'
    return file_contents


def verify_md5_sign(contents1,contents2):
    print 'MD5 values:'
    md5_1 = hashlib.md5(contents1[4:549]).hexdigest()
    md5_2 = hashlib.md5(contents2[4:549]).hexdigest()
    print 'cert1: '+ md5_1
    print 'cert2: '+ md5_2
    print '\nSHA values:'
    sha_1 = hashlib.sha1(contents1[4:549]).hexdigest()
    sha_2 = hashlib.sha1(contents2[4:549]).hexdigest()
    print 'cert1: '+ sha_1
    print 'cert2: '+ sha_2
    if md5_1 == md5_2 and sha_1 != sha_2 :
        print '\nWell! Collision seems effective!\ncheck your files in gen_certs/\n-------'
    else:
        print '\nBad collision :(\nplease consider rerunning program\n--------'

def gen_CA_sign(contents,data):    
    with open('./temp/CA_tbs','wb') as temp:
        temp.write(contents[4:520])
    
    os.system('openssl dgst -md5 -sign {} -out ./temp/CA_sig< ./temp/CA_tbs'.format(data))

    with open('./temp/CA_sig','rb') as sig:
        sig_contents=sig.read()
 
    contents1=contents[:539]+sig_contents
    return contents1


        
def gen_CA_files(data):
    os.system('openssl rsa -in {} -outform DER -pubout > ./temp/temp_CAkey.cer'.format(data))
    with open('./temp/temp_CAkey.cer','rb') as f1:
        with open('./CA_cert/CA.cer','rb') as f3:
            contents3=f3.read()
            contents1=f1.read()
            contents2=contents3[:224]+contents1[32:288]+contents3[480:]

    contents2=gen_CA_sign(contents2,data)            
    with open('./gen_certs/CA.cer','wb') as f2:
        f2.write(contents2)

    os.system('openssl x509 -in ./gen_certs/CA.cer -inform DER -out ./gen_certs/CA.pem')
    print 'Generating CA certificates.....[OK]'
        

def gen_sign(contents1,contents2,data,mybool):    
    with open('./temp/tbs1','wb') as temp1:
        temp1.write(contents1[4:549])
    with open('./temp/tbs2','wb') as temp2:
        temp2.write(contents2[4:549])

    if data is None and mybool is False:
        print 'Please enter path to CA rsa key (press enter to put a default one):'
        data = stdin.readline().strip()
        if data == '':
            data='./CA_cert/CA.key'
            
    if mybool is True:
        data='./CA_cert/CA.key'
                
    #gen_CA_files(data)
    
    os.system('openssl dgst -md5 -sign {} -out ./temp/sig1< ./temp/tbs1'.format(data))
    os.system('openssl dgst -md5 -sign {} -out ./temp/sig2< ./temp/tbs2'.format(data))

    with open('./temp/sig1','rb') as sig1:
        sig1_contents=sig1.read()
    with open('./temp/sig2','rb') as sig2:
        sig2_contents=sig2.read()

    contents1=contents1[:569]+sig1_contents
    contents2=contents2[:569]+sig2_contents
    return contents1,contents2


def random_prime(bitsize):
    x = random.randint(0, 1 << (bitsize - 1))
    return next_prime(x)

def random_prime_coprime(bitsize, n):
        x = random_prime(bitsize)
        if gcd(x - 1, n) == 1:
            return x
        else:
            return random_prime_coprime(bitsize, n)
                

def crt(a1,a2,n1,n2):
    N=n1*n2
    inv1= invert(n2,n1)
    inv2= invert(n1,n2)
    return -( a1*inv1*n2 + a2*inv2*n1)%N
        
def gen_rsakeys(contents,mybool):
    if mybool is False:
        print 'choose an option :\n--------------\n1. generate random key for collision demo (fast)\n2. generate real rsa keys (long)'
    while True:
        if mybool is True:
            selection='1'
        else:
            selection=raw_input("Please Select:")
            print('\n')
        
        if selection =='1':
            with open('./base_certs/rsa_template.cer','rb') as f:
                with open('./temp/temp1','wb') as f2:
                    contentsa=contents[4:]+f.read()
                    f2.write(contentsa)
            os.system('./fastcoll/build/fastcoll -p ./temp/temp1 -o ./temp/collout1 ./temp/collout2')
            print '\n\nGenerating more complete certificates....[OK]'
            with open('./base_certs/end_template.cer','rb') as f1:
                with open('./temp/collout1','rb') as f2:
                    contents1=contents[:4]+f2.read()+f1.read()
            with open('./base_certs/end_template.cer','rb') as f1:
                with open('./temp/collout2','rb') as f3:
                    contents2=contents[:4]+f3.read()+f1.read()
            break      

        elif selection == '2':
            print 'generating rsa key (may take a while) :\n\ncollision block:\n----------------'
            with open('./temp/temp2','wb') as f:
                f.write(contents[4:])
            os.system('./fastcoll/build/fastcoll -p ./temp/temp2 -o ./temp/collout1_1 ./temp/collout2_1')
            with open('./temp/collout1_1','rb') as f:
                contentsb=f.read()
            with open('./temp/collout2_1','rb') as f:
                contentsc=f.read()

            print '\n\nend block :\n---------------------\n\n'
            b1_1=contentsb[256:384]
            b2_1=contentsc[256:384]
            b1=int(binascii.hexlify(b1_1),16)
            b2=int(binascii.hexlify(b2_1),16)
            found=0
            i=0
            sys.stdout.write("generating :")
            while True:
                p1=random_prime_coprime(512,65537)
                p2=random_prime_coprime(512,65537)
                if p1 == p2:
                    continue
                p3=p1*p2
                b0=crt(b1*2**1024,b2*2**1024,p1,p2)
                k=0
                starttime=timeit.default_timer()
                while True:
                   b=b0+p3*k
                   if b >= 2**1024:
                       break
                   q1=(b1*2**1024+b)/p1
                   q2=(b2*2**1024+b)/p2
                   if is_prime(q1) and is_prime(q2) and gcd(q1-1,65537) == 1 and gcd(q2-1,65537) == 1 :
                       found = 1
                       endtime=timeit.default_timer()
                       time=endtime-starttime
                       print ('\nfound! running time: {}'.format(time))
                       sys.stdout.flush()
                       break
                   k+=1
                   
                if found == 1 :
                    break
                if i%50 == 0 :
                    sys.stdout.write(".")
                    sys.stdout.flush()
                i+=1
                
            #print len(hex(b))
            contents1=contents+b1_1+str(hex(b))
            contents2=contents+b2_1+str(hex(b))
            break

        else:
            print 'unknown option selected'

    return contents1,contents2
        


def verify_certificates(outname):
    os.system('openssl verify -CAfile ./gen_certs/CA.pem ./gen_certs/{}1.pem'.format(outname))
    os.system('openssl verify -CAfile ./gen_certs/CA.pem ./gen_certs/{}2.pem'.format(outname))

def clean_temp():
    os.system('rm temp/*')


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', metavar='in-file', help='base cer template file to use', type=argparse.FileType('rb'))
    parser.add_argument('-v', help='validate certificates', action='store_true')
    parser.add_argument('-d', help='demo mode', action='store_true')
    parser.add_argument('-c', help='clean temporary files after execution', action='store_true')
    parser.add_argument('--CAkey', metavar='in-CA-key', help='CA key pair')
    parser.add_argument('-o', metavar='output name', help='output name use when generating new certificates (will generate {new_name}1.cer and {new_name}2.cer')
    try:
        results = parser.parse_args()
    except IOError, msg:
        parser.error(str(msg))

    if results.i is not None :
        base_contents=results.i.read()
    else:
        with open('./base_certs/start_template.cer','rb') as infile1:
            base_contents=infile1.read()

    print 'Welcome to certificates collider basics generator\n-------------------------------------------------\n'
    print 'this program will help you build collinding x509 certificates based on MD5 signature. To do so, it will generate 2 certificates equal apart from a colliding rsa public key.\n'
    print 'if you used an input file on command line, you have already the start of a cer file (asn1 cimpliant) to work on. If not, you have been given an arbitrary starting cer file.\n'

    print 'first you will changes the parameters of the client in the certificates to be generated :\n----------------------------------------------------------------------------------------'
    base_contents = modify_parameters_menu(base_contents,results.d)

    print 'you will now generate rsa moduli for the certificates'
    base_contents1,base_contents2=gen_rsakeys(base_contents,results.d)

    print '\n\nyou will now generate the signature parts of the certificates'
    base_contents1,base_contents2=gen_sign(base_contents1,base_contents2,results.CAkey,results.d)

    genfile(base_contents1,base_contents2,results.o)
    verify_md5_sign(base_contents1,base_contents2)

    if results.v is True:
        verify_certificates(results.o)
    if results.c is True:
        clean_temp()    


main()                                
