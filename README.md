# ocsp request with bouncy castle 1.71 in POST request

. compile the src/root/Main.java in executable jar.<br/>
. pass the certificate to test as argument in console.<br/>
. the response status is the callback.<br/>

* the request to the ocsp responser server is POST. No GET.<br/>

* the RFC 2560 accept GET request if the ocsp request length is less than 255 bytes.
