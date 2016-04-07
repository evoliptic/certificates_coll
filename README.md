# certificates_coll
some progs for a practical little demonstration about colliding md5 signed based certificates, based on research "Colliding X.509 Certificates" made by wang, lestra and de berger.

installation
------------
following instructions are for Linux users on a debian based distro. Please adjust following with your OS.

  dependencies:
  -------------
	-fascoll program : boost libraries, cmake > 2.6
	-openssl  (should work with version > 0.9)
	-main program : python > 2.6 (should be installed by default), some non default installed python modules: gmpy2

  step by step:
  -------------
	if cmake is not installed:
	$ apt-get install cmake

	if boost libraries are not installed:
	$ apt-get install libboost-all-dev

	if openssl isn ot installed
	$ apt-get install openssl

	if gmpy is not installed
	$ apt-get install python-gmpy2
	
	$ cd {YOUR_PWD}
	$ git clone https://github.com/evoliptic/certificates_coll.git
	$ cd certificates_coll/fastcoll
	$ mkdir -p build/ && cd build/
	$ cmake ..
	$ make
	$ cd ../../




utilization
-----------
  $ python handle.py runs the program

  options :
	optionnal:
	  -h show help
	  -i based cer template infile (more explanations following)
	  -v check resulting colliding certificates against root one
	  --CAkey generated key pair for CA without cbc protection and 2048 bits length(obtained from 'openssl genrsa -out CA.key 2048')
	  -o output name to use (will generate {new_name}1.cer and {new_name}2.cer in gen_certs/
	  -c clean temporary files used
	  -d demo mode, avoiding user input just to show and see time to generation



explanations about how the program works
----------------------------------------
the program works generally as the following :
it generates two certificates colliding under md5 in the rsa public key part, as all fields except rsa key are same, and at the end same md5 of the 'to be signed ' part is found. In this sense, signature part is the same at the end of both. The method is taken from the research paper made from scientits cited upper : Wang, de Werger and Lestra (paper : https://www.win.tue.nl/~bdeweger/CollidingCertificates/). The collisions finder subprogram used is the program fastcoll, made by Marc Stevens (http://www.win.tue.nl/hashclash/).


|-----------|      |----------|    |----------|
| start     | ===> |     1    |    |     1    |
| fields    |      |----------|  + |----------|            we have here md5(2)=md5(3)
|-----------|      |rsa key 1 |    |rsa key 2 |
                   |----------|    |----------|
     1                  2               3

step 1:
it takes in entry a pwd towards a CA key pair and a starting template of a certificate in cer format.
This CA key pair must be of 2048 bit length key __cf__and must not be protected using cbc mode__. It can be generated using the following command '$openssl genrsa 2048'.
the starting template consists in the first 260 bytes of a certificate in cer format, thus verifying asn1 structures.
If the starting template is provided and demo mode is activated, then the user will jump to step 2. Elsewise, the program will use a default starting template or the template entered and asks the user to to midfy it by entering its own fields in the attributes 'common name','country', 'location' and 'comment', that must be the same length than the ones already in the template (in order to not mess up with the asn1 structure and md5 calculation(the user can generate its own structure and provide it still)(note: the user may leave his structure untouched).
After all fields are entered, we go to step 2.

step 2:
the next step is the generation of rsa colliding keys for md5. Two methods can be used here :
the first one, which is fast (approximately 30sec to 1 minute) generates random colliding rsa like keys, but without any mathematical ingredient behind.
the second one, instead, generates real colliding keys, in the sense that mathematical parts of it are achieved and we have the private key associated (we could so generate sub certificates for example). (Note: in terms of security, the coefficients p and q such that n=p*q are pretty unbalanced here).

step 3:
signatures parts of the two certificates are generated using the key pair entered, and if the user wants it, the CA certificate is also generated from the key pair entered. If the user did not entered any pwd to key pair and is not in demo mode, then the program will ask for one pwd to key pair if in demo, we use a template key pair.

step 4:
ending: the 'to be signed part' can be passed through md5 and sha1 to show properties

performances:
-------------
depending a lot on hardware, takes around 30-90seconds when generating random collision, can takes up to 40minutes when searching for fully crafted rsa keys.


not implemented:
----------------
automating numbers for templates


Future :
--------
One of the wish of the people who made that program was to generate real different usable certificates that still collide using hashclash (fastcoll program made to be used with cuda by Marc Stevens also) based on this infos: https://www.win.tue.nl/hashclash/rogue-ca/
Unfortunately, some tests show that it would require around 20 days to generate those certificates on our machine, and getting parralelizing hardware to do the job (as well as maybe rewrite all parallelizing parts of hashclash) was out of scope for this school project.



TODO list:
----------
- check for validated time certifs
- numbers for modify param
- review for final

