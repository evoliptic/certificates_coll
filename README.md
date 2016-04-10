# certificates_coll
some progs for a practical little demonstration about colliding md5 signed based certificates, based on research "Colliding X.509 Certificates" made by wang, lestra and de Werger.

installation
------------
following instructions are for Linux users on a debian based distro. Please adjust following with your OS.

  dependencies:
  -------------
	-fascoll program : boost libraries, cmake > 2.6 (credits go to Marc Stevens)
	-openssl  (should work with version > 0.9)
	-main program : python > 2.6 (should be installed by default), some non default installed python modules: gmpy2

  step by step:
  -------------
	if cmake is not installed:
	$ apt-get install cmake

	if boost libraries are not installed:
	$ apt-get install libboost-all-dev

	if openssl is not installed
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
	  --inCer starting cer template infile (more explanations following)
	  --inCACer input template for CA certificate
	  -v check resulting colliding certificates against root one
	  --CAkey generated key pair for CA without cbc protection and 2048 bits length(obtained from 'openssl genrsa -out CA.key 2048')
	  -o output name to use for generated certificates (will generate {new_name}1.cer and {new_name}2.cer in gen_certs/
	  -c clean temporary files used
	  -d demo mode, avoiding user input just to show and see time to generation



explanations about how the program works
----------------------------------------
the program works generally as the following :
it generates two certificates colliding under md5 in the rsa public key part, as all fields except rsa key are same. At the end same md5 of the 'to be signed ' part is found and in this sense, signature part is the same at the end of both. The method is taken from the research paper made from scientits cited upper : Wang, de Werger and Lestra (paper : https://www.win.tue.nl/~bdeweger/CollidingCertificates/). The MD5 collisions finder subprogram used is the program fastcoll, made by Marc Stevens (http://www.win.tue.nl/hashclash/).


step 0:
the program takes three files as input to generate the certificates : 
 - a CA key pair of 2048 bit length key (it can be protected using cbc mode). It can be generated using the following command '$openssl genrsa 2048'. this key pair will be used to generate the signature part of the colliding certificates
 - a starting template, that consists in the any first 260 bytes of a certificate in cer format(binary format), thus verifying asn1 structures.
 - a CA template, consisting of a template with the same structure than the template named base_certs/CA_template.cer, where the user can modify only the fields 'common name', 'country' and 'location' (and date by hand)

those files are optionnal in the sense that the program will use default ones to generate the certificates or ask the user if not provided and needed, when running. In fact, they can be used in the case the user wants to modify fields of certificates.
the CA template will be useful only if the option '-g' ,that generates the CA certificates, is selected.

step 1:
If demo mode is activated, then the user will jump to step 2.
Elsewise, the program will use a default starting template or the template entered and asks the user to modify it by entering its own fields in the attributes 'common name','country', 'location' and 'comment'. For this part, we ask the user to have the same global structure than the template 'base_certs/start_template.cer', thus having fields at the same position and that must be the same length than the ones already in the template (in order to not mess up with the asn1 structure and md5 calculation(the user can generate its own structure and provide it still)(note: the user may leave his structure untouched) (user can find the reason behind that in "not implemented" paragraph. 
if -g option is selected, the program will also asks the user if he wants to modify the fields 'country', 'common name', and 'location' of CA certificate, updating also the client certificate. Here also, we ask the user to have the same global structure than the CA template(same positions and lengths of fields).
After all fields are entered, we go to step 2.

step 2:
the next step is the generation of rsa colliding keys for md5. Two methods can be used here :
the first one, which is fast (approximately 30sec to 1 minute) generates random colliding rsa like keys, but without any mathematical ingredient behind.
the second one, much more longer, instead, generates random colliding keys, but achieves mathematical parts of it: we have the private key associated and such (we could so generate sub certificates for example). (Note: in terms of security, the coefficients p and q such that n=p*q are pretty unbalanced here in length of bits).

step 3:
signatures parts of the two certificates are generated using the key pair entered, and if the user wants it, the CA certificate is also generated from the CA template (obtained either from entered one or from modified one on step 1) and the key pair entered. If the user did not entered any pwd to key pair and is not in demo mode, then the program will ask for one pwd to key pair. If in demo, we use a template key pair.

step 4:
ending: the 'to be signed part' can be passed through md5 and sha1 to show properties and verify collision, and the user can ask for a verification against the CA certificate.

performances:
-------------
depending a lot on hardware and is hazardous (as our method is based on randomness), takes around 30-90seconds when generating random collision, can takes up to 40minutes when searching for fully mathematically crafted random rsa keys.


not implemented:
----------------
one of feature of the program would be to let the user modify the differents fields of any entered starting template at the beginning. However, as those starting templates should verify their bits length can be divided by 128, we could assume that the user has already crafted compliant template. More, due to optionnal and redondants possible fields in the templates, as well as untrusted user input, and the fact that certificates are somewhat attached to the CA one, we can't make sure the template entered won't screw up completly the program. Due to this, only the modification of relevant fields in the default starting templates (both for CA and cerficate) is implemented.


Future :
--------
One of the wish of the people who made that program was to generate real different usable certificates that still collide using hashclash (fastcoll program made to be used with cuda by Marc Stevens also) based on this infos: https://www.win.tue.nl/hashclash/rogue-ca/
Unfortunately, some tests show that it would require around 20 days to generate those certificates on our machine, and getting parralelizing hardware to do the job (as well as maybe rewrite all parallelizing parts of hashclash) was out of scope for this school project.


