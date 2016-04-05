#!/usr/bin/env python

import binascii
import sys
from sys import stdin
import hashlib
import os
import argparse

def genfile(base_contents1,base_contents2):
    with open('./gen_certs/certificate1.cer','wb') as outfile1:
        outfile1.write(base_contents1)

    with open('./gen_certs/certificate2.cer','wb') as outfile2:
        outfile2.write(base_contents2)



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




def modify_parameters_menu(file_contents):
    menu = {}
    print('[within options 1,2,3 and 4 of menu, we ask that total length of new value for the chosen parameter is equal to the length of the previous one (in order to not break whole structure). within option 5, you must provide a whole new asn1 starting part of the certificate(260 bytes length). If you don\'t want to modify any parameter, enter option 6]\n')
    menu['1']="modify common name"
    menu['2']="modify country"
    menu['3']="modify location"
    menu['4']="modify comment"
    menu['5']="modify total head of certificate"
    menu['6']="Exit parameters modifications"

    #!!!!TO DO!!!!!!
    #need to provide a way to calculate numbers automatically here to adjust to all templates
    while True:
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
        


def gen_sign(contents1,contents2):    
    with open('./temp/tbs1','wb') as temp1:
        temp1.write(contents1[4:549])
    with open('./temp/tbs2','wb') as temp2:
        temp2.write(contents2[4:549])

    print 'Please enter path to CA rsa key:'
    data = stdin.readline().strip()

    #todo: might consider replacing quite deprecated os.system
    os.system('openssl dgst -md5 -sign {} -out ./temp/sig1< ./temp/tbs1'.format(data))
    os.system('openssl dgst -md5 -sign {} -out ./temp/sig2< ./temp/tbs2'.format(data))

    with open('./temp/sig1','rb') as sig1:
        sig1_contents=sig1.read()
    with open('./temp/sig2','rb') as sig2:
        sig2_contents=sig2.read()

    contents1=contents1[:569]+sig1_contents
    contents2=contents2[:569]+sig2_contents
    return contents1,contents2


def gen_rsakeys(contents):
    #test with fake keys for now
    #
    #need to write extern file to generate good based IV for fastcoll
    #TODO: why the fuck?
    #
    #TODO 2: implement the good rsa thing

    print 'choose an option :\n--------------\n1. generate random key for collision demo (fast)\n2. generate real rsa keys (long)'
    while True:
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
            #todo2
            break

        else:
            print 'unknown option selected'

    return contents1,contents2
        


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', metavar='in-file', type=argparse.FileType('rb'))

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
    base_contents = modify_parameters_menu(base_contents)

    print 'you will now generate rsa moduli for the certificates'
    base_contents1,base_contents2=gen_rsakeys(base_contents)

    print 'you will now generate the signature parts of the certificates'
    base_contents1,base_contents2=gen_sign(base_contents1,base_contents2)

    genfile(base_contents1,base_contents2)
    verify_md5_sign(base_contents1,base_contents2)            
    
main()                                
