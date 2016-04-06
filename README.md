# certificates_coll
some progs for a practical little demonstration about colliding md5 signed based certificates, based on research "Colliding X.509 Certificates" made by wang, lestra and de berger

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
	  -ca-key generated key pair for CA without cbc protection and 2048 bits length(obtained from 'openssl genrsa -out CA.key 2048')



explanations about how the program works
----------------------------------------
blahblahblah

TODO list:
----------
- finish readme
- implement the real rsa generation ------> ok but have to check for ending
- verify the ca certificate generation 
- implement all options: output name, ca-key (en cours)
- go a bit more user friendly
- review possibly deprecated methods



