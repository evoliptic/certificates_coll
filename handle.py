#!/usr/bin/env python

import binascii
import sys
from sys import stdin
import hashlib

def genfile(base_contents1,base_contents2):
    with open('./gen_certs/certificate1.cer','wb') as outfile1:
        outfile1.write(base_contents1)

    with open('./gen_certs/certificate2.cer','wb') as outfile2:
        outfile2.write(base_contents2)



def modify_contents(file_contents1, file_contents2, start, end, name):
    base_len=end-start
    print ('----------\nyou chose to modify {}, you must enter a length of {}\n new string:'.format(name,base_len))

    data = stdin.readline()
    data=data.strip()
    if len(data) != base_len :
        print 'wrong length entered, quitting modification'
    else :
        file_contents1=file_contents1[0:start]+data+file_contents1[end:]
        file_contents2=file_contents2[0:start]+data+file_contents2[end:]

    return file_contents1,file_contents2




def modify_parameters_welcome(file_contents1,file_contents2):
    menu = {}
    print('-------------------------\nwithin options 1,2,3 and 4 of menu, we ask that total length of new string is equal the previous one. within option 5, be aware that this option is hard(you need to generate correct asn structure) and that total length must be divided by 64.')
    menu['1']="modify common name"
    menu['2']="modify country"
    menu['3']="modify location"
    menu['4']="modify comment"
    menu['5']="modify total head of certificate"
    menu['6']="Exit parameters modifications"

    while True:
        options=menu.keys()
        options.sort()
        for entry in options:
            print entry, menu[entry]
        selection=raw_input("Please Select:")
        print('\n')
        if selection =='1':
            print "you selected option1"
            file_contents1,file_contents2=modify_contents(file_contents1,file_contents2,142,156,'common name')
        elif selection == '2':
            print "you selected option2"
            file_contents1,file_contents2=modify_contents(file_contents1,file_contents2,225,227,'country')
        elif selection == '3':
            print "you selected option3"
            file_contents1,file_contents2=modify_contents(file_contents1,file_contents2,205,214,'location')
        elif selection == '4':
            print "you selected option4"
            file_contents1,file_contents2=modify_contents(file_contents1,file_contents2,167,194,'comment')
        elif selection == '5':
            print "you selected option5"
            file_contents1,file_contents2=modify_contents(file_contents1,file_contents2,0,256,'all')
        elif selection == '6':
            break
        else:
            print "Unknown Option Selected!"
        print '\n--------\nnew option:'

    print '\nGenerating new cer files... [OK]\n\n'
    return file_contents1,file_contents2


def verify_md5_sign(contents1,contents2):
    """
    for i in xrange(5,825) :
        md5_1 = hashlib.md5(contents1[4:i]).hexdigest()
        if md5_1 == "5fa5531b3fba6973fef68ba52d32e617" :
            print ('found at length {}'.format(i))
    """
    print 'MD5 values:'
    md5_1 = hashlib.md5(contents1[4:580]).hexdigest()
    md5_2 = hashlib.md5(contents2[4:580]).hexdigest()
    print contents1[256:]
    print 'cert1: '+ md5_1
    print 'cert2: '+ md5_2
    print '\nSHA values:'
    sha_1 = hashlib.sha1(contents1[4:549]).hexdigest()
    sha_2 = hashlib.sha1(contents2[4:549]).hexdigest()
    print 'cert1: '+ sha_1
    print 'cert2: '+ sha_2
    if md5_1 == md5_2 and sha_1 != sha_2 :
        print '\nWell! Collision seems effective\n------\n'
    else:
        print '\nBad collision :(\n-------\n'


def gen_sign(contents1,contents2):
    #os.exec(openssl dgst....)
    return contents1,contents2

        
        
def welcome():

    menu = {}
    menu['1']="modificates base cer files with own parameters"
    menu['2']="verify md5sum of to be signed part"
    menu['3']="generate compliant rsa keys (not implemented yet)"
    menu['4']="generate certificates with sign"
    menu['5']="Exit"

    with open('./base_certs/MD5Collision.certificate1.cer','rb') as infile1:
        base_contents1=infile1.read()
        
    with open('./base_certs/MD5Collision.certificate2.cer','rb') as infile2:
        base_contents2=infile2.read()       
        
    while True:
        options=menu.keys()
        options.sort()
        for entry in options:
            print entry, menu[entry]
        selection=raw_input("Please Select:")
        print('\n')
        if selection =='1':
            base_contents1,base_contents2 = modify_parameters_welcome(base_contents1,base_contents2)
            genfile(base_contents1,base_contents2)
        elif selection == '2':
            verify_md5_sign(base_contents1,base_contents2)            
        elif selection == '3':
            print "find"
        elif selection == '4':
            break
        elif selection == '5':
            break
        else:
            print "Unknown Option Selected!"
        print 'choose an option :'

welcome()
                                
