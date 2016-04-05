#!/usr/bin/env python

import binascii
import sys
from sys import stdin
import hashlib
import os

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
        print data
        print len(data)
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
    print 'MD5 values:'
    md5_1 = hashlib.md5(contents1[4:549]).hexdigest()
    md5_2 = hashlib.md5(contents2[4:549]).hexdigest()
    print 'cert1: '+ md5_1
    print 'cert2: '+ md5_2
    #verifying
    """
    md5_1 = hashlib.md5(contents1[4:388]).hexdigest()
    md5_2 = hashlib.md5(contents2[4:388]).hexdigest()
    print 'cert1: '+ md5_1
    print 'cert2: '+ md5_2
    """
    """
    md5_1 = hashlib.md5(contents1[4:260]).hexdigest()
    md5_2 = hashlib.md5(contents2[4:260]).hexdigest()
    print 'cert1: '+ md5_1
    print 'cert2: '+ md5_2
    """
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
    with open('./temp/tbs1','wb') as temp1:
        temp1.write(contents1[4:549])
    with open('./temp/tbs2','wb') as temp2:
        temp2.write(contents2[4:549])
        
    os.system('openssl dgst -md5 -sign ./CA_cert/CA.key -out ./temp/sig1< ./temp/tbs1')
    os.system('openssl dgst -md5 -sign ./CA_cert/CA.key -out ./temp/sig2< ./temp/tbs2')
    
    with open('./temp/sig1','rb') as sig1:
        sig1_contents=sig1.read()
    with open('./temp/sig2','rb') as sig2:
        sig2_contents=sig2.read()

    contents1=contents1[:569]+sig1_contents
    contents2=contents2[:569]+sig1_contents
    genfile(contents1,contents2)
    return contents1,contents2

def gen_rsakeys(contents1,contents2):
    #test with fake keys for now
    #md5 = hashlib.md5(contents1[4:260]).hexdigest()
    #print md5
    #os.system('./fastcoll/build/fastcoll -i %s -o ./temp/coll1 ./temp/coll2'% (md5))

    #wi5555555555555555th open ('./temp/tbs1','rb') as tbs:
    with open ('./temp/testin','wb') as testin:
    #        contents=tbs.read()
        testin.write(contents1[4:260])
            
    os.system('./fastcoll/build/fastcoll -p ./temp/testin -o ./temp/collout1 ./temp/collout2')
    """
    with open('./temp/coll1','rb') as coll1:
        coll1_contents=coll1.read()
    with open('./temp/coll2','rb') as coll2:
        coll2_contents=coll2.read()
    temp_contents=contents1[4:260]+coll1_contents    
    temp_contents2=contents1[4:260]+coll2_contents
    md5 = hashlib.md5(temp_contents).hexdigest()
    print md5
    """
    os.system('./fastcoll/build/fastcoll -p ./temp/collout1 -o ./temp/collout1_1 ./temp/collout1_2')
    
    with open('./temp/collout1_1','rb') as coll1_1:
        coll1_1_contents=coll1_1.read()
    with open('./temp/collout1_2','rb') as coll1_2:
        coll1_2_contents=coll1_2.read()
    
    contents1=contents1[:4]+coll1_1_contents+contents1[516:]
    contents2=contents2[:4]+coll1_2_contents+contents2[516:]
    """
    with open('./temp/tbs_coll1','wb') as colla:
        colla.write(contents1[4:549])
    with open('./temp/tbs_coll2','wb') as collb:
        collb.write(contents2[4:549])
    """
    genfile(contents1,contents2)
#    os.system('./fastcoll/build/fastcoll -i %s -o ./temp/coll1 ./temp/coll2'% (md5_1))
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
            base_contents1,base_contents2=gen_rsakeys(base_contents1,base_contents2)
        elif selection == '4':
            base_contents1,base_contents2=gen_sign(base_contents1,base_contents2)
        elif selection == '5':
            break
        else:
            print "Unknown Option Selected!"
        print 'choose an option :'

welcome()
                                
