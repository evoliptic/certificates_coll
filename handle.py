#!/usr/bin/env python

"""
 software made by Zilio,Cauchon
 distributed under GnuPl v3 license
 certificates_coll copyright 2016 
"""




import binascii
import sys
from sys import stdin
import hashlib
import os
import struct
import argparse
import base64
import random
from gmpy2 import *
import time
import subprocess

"""
this function generates the final certificates in format cer and pem in the output directory gen_certs.
input :
       base_contents1 the string reprensatating the first certificate in cer format
       base_contents2 the string reprensatating the second certificate in cer format
       outname the name of the output certificates, will be appended with 1 and 2
"""
def genfile(base_contents1,base_contents2,outname):
    if outname is None:
        outname='certificate'
    with open('./gen_certs/{}1.cer'.format(outname),'wb') as outfile1:
        outfile1.write(base_contents1)
    with open('./gen_certs/{}2.cer'.format(outname),'wb') as outfile2:
        outfile2.write(base_contents2)
    subprocess.call('openssl x509 -in ./gen_certs/{}1.cer -inform DER -out ./gen_certs/{}1.pem'.format(outname,outname), shell=True)
    subprocess.call('openssl x509 -in ./gen_certs/{}2.cer -inform DER -out ./gen_certs/{}2.pem'.format(outname,outname),shell=True)


"""
this function permits to modify the contents of the start template used in the program
input :
       file_contents the template to modify
       start the starting index of the modification to take place
       end the ending index of the modification to take place
       name the name of the field being modificated

output :
        the modified template
"""
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

def modify_ca_contents(ca_contents,file_contents, start, end,start2,end2,name):
    base_len=end-start
    print ('----------\nyou chose to modify {},with actual value"{}" you must enter a length of {}\n new string:'.format(name,ca_contents[start:end],base_len))

    data = stdin.readline()
    data=data.strip()
    if len(data) != base_len :
        print 'wrong length entered, quitting modification'
    else :
        ca_contents=ca_contents[0:start2]+data+ca_contents[end2:start]+data+ca_contents[end:]
        file_contents=file_contents[0:start2]+data+file_contents[end2:]
    return ca_contents, file_contents


"""
menu to modify the several parameters of the start template of our server certificate
input :
       file_contents the starting template to modify
       mybool boolean to see if demo mode is activated or not (if activated the user won't have any interaction here)
       ca_contents the template of CA certificate
       mybool2 check if generation of CA certificate is selected

output :
        the modified templates
"""
def modify_parameters_menu(file_contents, mybool, ca_contents, mybool2):
    menu = {}
    print 'modifying client template'
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

    menu = {}
    print 'modifying CA template'
    print('[within options 1,2 and 3 of menu, we ask that total length of new value for the chosen parameter is equal to the length of the previous one (in order to not break whole structure). If you don\'t want to modify any parameter, enter option 4]\n')
    menu['1']="modify common name"
    menu['2']="modify country"
    menu['3']="modify location"
    menu['4']="Exit parameters modifications"

    while True:
        if mybool2 is False or mybool is True:
            break
        options=menu.keys()
        options.sort()
        for entry in options:
            print entry, menu[entry]
        selection=raw_input("Please Select:")
        print('\n')
        if selection =='1':
            print "you selected option1"
            ca_contents,file_contents=modify_ca_contents(ca_contents,file_contents,142,159,47,64,'common name')
        elif selection == '2':
            print "you selected option2"
            ca_contents,file_contents=modify_ca_contents(ca_contents,file_contents,190,192,95,97,'country')
        elif selection == '3':
            print "you selected option3"
            ca_contents,file_contents=modify_ca_contents(ca_contents,file_contents,170,179,75,84,'location')
        elif selection == '4':
            break
        else:
            print "Unknown Option Selected!"
        print '\n--------\nnew option:'
    print '\nGenerating new CA cer template... [OK]\n\n'


    return file_contents, ca_contents


"""
this function verifies the md5 and sha1 values of the 'to be signed' parts of certificates, and print if collision is effective or not
input :
       contents1 buffer representing cer of first certificate
       contents2 buffer representing cer of second certificate
"""
def verify_md5_sign(contents1,contents2):
    print 'verifying signatures:\n------------------'
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



"""
this function generates the signature part of the CA certificate
input :
       contents buffer representating the CA certificate
       data pwd to CA key pair

output : 
        the modified buffer with good signature representing the CA certificate
"""
def gen_CA_sign(contents,data):    
    with open('./temp/CA_tbs','wb') as temp:
        temp.write(contents[4:520])
    p1=subprocess.call('openssl dgst -md5 -sign {} -out ./temp/CA_sig < ./temp/CA_tbs'.format(data), shell=True)
    with open('./temp/CA_sig','rb') as sig:
        sig_contents=sig.read()
 
    contents1=contents[:540]+sig_contents
    return contents1


"""
this functions makes the necessary to generate a CA certificate
input :
       data pwd to CA key pair
       data2 pwd to CA cer template
output : 
        a CA certificate with the name 'CA' is created in the directory gen_certs/
"""
def gen_CA_files(data,ca_contents):
    subprocess.call('openssl rsa -in {} -outform DER -pubout -out ./temp/temp_CAkey.cer >/dev/null 2>&1'.format(data),stdout=None,shell=True)
    with open('./temp/temp_CAkey.cer','rb') as f1:
        contents1=f1.read()

    ca_contents=ca_contents[:225]+contents1[33:289]+ca_contents[481:]
    ca_contents=gen_CA_sign(ca_contents,data)            

    with open('./gen_certs/CA.cer','wb') as f2:
        f2.write(ca_contents)
    subprocess.call('openssl x509 -in ./gen_certs/CA.cer -inform DER -out ./gen_certs/CA.pem',shell=True)
    print 'Generating CA certificates.....[OK]\n\n'


    
"""
this function creates the signatures part of our colliding certificates, and creates the CA certificates if wanted in the mean time
note: we could normally calculate the signature of only one certificate, as the second should colliding, but we calculate here the two, as it permits to check if there is collision or not
input :
       contents1 buffer representing first certificate
       contents2 buffer representing second certificate
       data pwd to CA key pair
       mybool check if CA key pair was already entered on command line
       mybool2 boolean to see if we should generate CA certificate or not
       data2 pwd to CA template
output :
        the modified buffers representing our colliding certificates (that should be complete now)
"""
def gen_sign(contents1,contents2,ca_contents,data, mybool,mybool2):    
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
                
    if mybool2 is True:
        gen_CA_files(data,ca_contents)
    
    subprocess.call('openssl dgst -md5 -sign {} -out ./temp/sig1< ./temp/tbs1'.format(data),shell=True)
    subprocess.call('openssl dgst -md5 -sign {} -out ./temp/sig2< ./temp/tbs2'.format(data),shell=True)

    with open('./temp/sig1','rb') as sig1:
        sig1_contents=sig1.read()
    with open('./temp/sig2','rb') as sig2:
        sig2_contents=sig2.read()

    contents1=contents1[:569]+sig1_contents
    contents2=contents2[:569]+sig2_contents
    return contents1,contents2



"""
function to generate a random prime of a given bits size
input :
       the bits size wanted for our number

output :
        a random prime of approximately the bitsize
"""
def random_prime(bitsize):
    x = random.randint(0, 1 << (bitsize - 1))
    return next_prime(x)



"""
function to generate a random prime which verifies that this prime is coprime with the entered number
input :
       bitsize the bits size wanted for our number
       n the number to be coprime with

output :
        a random prime coprime with n
"""
def random_prime_coprime(bitsize, n):
        x = random_prime(bitsize)
        if gcd(x - 1, n) == 1:
            return x
        else:
            return random_prime_coprime(bitsize, n)
                

"""
function to calculate a said number equal to some modulos using the chinese reminder theorem 

input :
      a1 the right member of first equation moduli
      a2 the right member of second equation moduli
      n1 the first moduli
      n2 the second moduli

output :
        the number verifying the following equations: x%n1=a1
                                                      x%n2=a2
"""
def crt(a1,a2,n1,n2):
    N=n1*n2
    inv1= invert(n2,n1)
    inv2= invert(n1,n2)
    return (-( a1*inv1*n2 + a2*inv2*n1))%N

"""
function to write the rsa mathematics to files
input :
       rsa coeffs
output :
       files asn1 compliant for rsa keys
"""
def gen_rsa_mathematics(p1,q1,p2,q2,n1,n2):
    phi1=(p1-1)*(q1-1)
    d1=invert(65537,phi1)
    exponent1_1=d1%(p1-1)
    exponent1_2=d1%(q1-1)
    coefficient1=invert(q1,p1)
    with open('./gen_certs/rsa_key1.txt','w') as f:
        f.write('asn1=SEQUENCE:rsa_key\n\n[rsa_key]\nversion=INTEGER:0\nmodulus=INTEGER:{}\npubExp=INTEGER:65537\nprivExp=INTEGER:{}\np=INTEGER:{}\nq=INTEGER:{}\ne1=INTEGER:{}\ne2=INTEGER:{}\ncoeff=INTEGER:{}'.format(n1,d1,p1,q1,exponent1_1,exponent1_2,coefficient1))

    phi2=(p2-1)*(q2-1)
    d2=invert(65537,phi2)
    exponent2_1=d2%(p2-1)
    exponent2_2=d2%(q2-1)
    coefficient2=invert(q2,p2)
    with open('./gen_certs/rsa_key2.txt','w') as f:
        f.write('asn1=SEQUENCE:rsa_key\n\n[rsa_key]\nversion=INTEGER:0\nmodulus=INTEGER:{}\npubExp=INTEGER:65537\nprivExp=INTEGER:{}\np=INTEGER:{}\nq=INTEGER:{}\ne1=INTEGER:{}\ne2=INTEGER:{}\ncoeff=INTEGER:{}'.format(n2,d2,p2,q2,exponent2_1,exponent2_2,coefficient2))

    
"""
function to generate the rsa key in the certificates. can generate random but non fully calculated colliding rsa keys fastly, or fully calculated ones but it takes longer

input :
       contents the first part of certificate in cer format
       mybool boolean to see if in demo mode (if in demo mode, random colliding rsa keys are generated)

output :
       two buffers representing colliding not full complete certificates
""" 
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
            subprocess.call('./fastcoll/build/fastcoll -p ./temp/temp1 -o ./temp/collout1 ./temp/collout2',shell=True)
            with open('./base_certs/end_template.cer','rb') as f1:
                with open('./temp/collout1','rb') as f2:
                    contents1=contents[:4]+f2.read()+f1.read()
            with open('./base_certs/end_template.cer','rb') as f1:
                with open('./temp/collout2','rb') as f3:
                    contents2=contents[:4]+f3.read()+f1.read()
            break      

        elif selection == '2':
            print 'generating rsa key (may take a while) :\n------------------------------\ncollision block:\n------------------'
            with open('./temp/temp2','wb') as f:
                f.write(contents[4:])
            subprocess.call('./fastcoll/build/fastcoll -p ./temp/temp2 -o ./temp/collout1_1 ./temp/collout2_1',shell=True)
            with open('./temp/collout1_1','rb') as f:
                contentsb=f.read()
            with open('./temp/collout2_1','rb') as f:
                contentsc=f.read()

            print '\n\nend block :\n---------------------'
            b1_1=contentsb[256:]
            b2_1=contentsc[256:]
            b1=int(binascii.hexlify(b1_1),16)
            b2=int(binascii.hexlify(b2_1),16)
            found=0
            i=0
            sys.stdout.write("generating :")
            sys.stdout.flush()
            starttime=time.time()
            while True:
                p1=random_prime_coprime(512,65537)
                p2=random_prime_coprime(512,65537)
                if p1 == p2:
                    continue
                p3=p1*p2
                b0=crt(b1*2**1024,b2*2**1024,p1,p2)
                k=0
                while True:
                   b=b0+p3*k
                   if b >= 2**1024:
                       break
                   q1=(b1*2**1024+b)/p1
                   q2=(b2*2**1024+b)/p2
                   if is_prime(q1) and is_prime(q2) and gcd(q1-1,65537) == 1 and gcd(q2-1,65537) == 1 :
                       found = 1
                       endtime=time.time()
                       tottime=endtime-starttime
                       gen_rsa_mathematics(p1,q1,p2,q2,b1*2**1024+b,b2*2**1024+b)
                       print ('\nfound! running time: {}m {}s'.format(int(round(tottime)/60),round(tottime)%60))
                       sys.stdout.flush()
                       break
                   k+=1
                   
                if found == 1 :
                    break
                if i%50 == 0 :
                    sys.stdout.write(".")
                    sys.stdout.flush()
                i+=1
            
            b_str=binascii.unhexlify('{:0{}x}'.format(b, int(1024/4)))
            with open('./base_certs/end_template.cer','rb') as f1:
                contents1=contents+b1_1+b_str+f1.read()
            with open('./base_certs/end_template.cer','rb') as f1:
                contents2=contents+b2_1+b_str+f1.read()

            print '\n\nGenerating more complete certificates....[OK]'
            break

        else:
            print 'unknown option selected'

    return contents1,contents2
        


"""
function to check created colliding certificates against the CA certificate
input :
       outname the starting of the name of output certificates
"""
def verify_certificates(outname):
    if outname is None:
        outname='certificate'
    print 'making the check against CA certificate :'
    subprocess.call('openssl verify -CAfile ./gen_certs/CA.pem ./gen_certs/{}1.pem'.format(outname),shell=True)
    subprocess.call('openssl verify -CAfile ./gen_certs/CA.pem ./gen_certs/{}2.pem'.format(outname),shell=True)


    
"""
function to clean temporary files used
"""
def clean_temp():
    subprocess.call('rm -r temp/',shell=True)


    
"""
main function: options parser and calling all others
"""
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--inCer', metavar='in-cer-file', help='base cer template file to use', type=argparse.FileType('rb'))
    parser.add_argument('--inCACer', metavar='in-CAcer-file', help='base CA cer template file to use', type=argparse.FileType('rb'))
    parser.add_argument('-v', help='validate certificates', action='store_true')
    parser.add_argument('-d', help='demo mode', action='store_true')
    parser.add_argument('-g', help='generate CA certificate', action='store_true')
    parser.add_argument('-c', help='clean temporary files after execution', action='store_true')
    parser.add_argument('--CAkey', metavar='in-CA-key', help='CA key pair')
    parser.add_argument('-o', metavar='output name', help='output name use when generating new certificates (will generate {new_name}1.cer and {new_name}2.cer')
    try:
        results = parser.parse_args()
    except IOError, msg:
        parser.error(str(msg))

    if not os.path.exists('temp'):
        os.makedirs('temp')    
    if not os.path.exists('gen_certs'):
        os.makedirs('gen_certs')    

    if results.inCer is not None :
        base_contents=results.inCer.read()
    else:
        with open('./base_certs/start_template.cer','rb') as infile1:
            base_contents=infile1.read()

    if results.inCACer is not None :
        base_CA_contents=results.inCACer.read()
    else:
        with open('./base_certs/CA_template.cer','rb') as infile1:
            base_CA_contents=infile1.read()


    print 'Welcome to certificates collider basics generator\nmade by Zilio,Cauchon  distributed under GnuPlv3\n-------------------------------------------------\n'
    print 'this program will help you build collinding x509 certificates based on MD5 signature. To do so, it will generate 2 certificates equal apart from a colliding rsa public key.\n'
    print 'if you used an input file on command line, you have already the start of a cer file (asn1 cimpliant) to work on. If not, you have been given an arbitrary starting cer file.\n'

    print 'first you will changes the parameters of the client in the certificates to be generated :\n----------------------------------------------------------------------------------------'


    base_contents,base_CA_contents = modify_parameters_menu(base_contents,results.d,base_CA_contents,results.g)

    print 'you will now generate rsa moduli for the certificates\n'
    base_contents1,base_contents2=gen_rsakeys(base_contents,results.d)

    print '\n\ngenerating the signature parts of the certificates.....[OK]\n'
    base_contents1,base_contents2=gen_sign(base_contents1,base_contents2,base_CA_contents,results.CAkey,results.d,results.g)

    genfile(base_contents1,base_contents2,results.o)
    verify_md5_sign(base_contents1,base_contents2)

    if results.v is True:
        verify_certificates(results.o)
    if results.c is True:
        clean_temp()    

"""
running program
"""
main()                                
