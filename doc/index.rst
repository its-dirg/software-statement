.. Software Statement documentation master file, created by
   sphinx-quickstart on Thu Jun 18 10:45:52 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Software Statement's documentation!
==============================================

Contents:

.. toctree::
   :maxdepth: 2



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


Software API publisher
----------------------

The software API publisher is the one that can sign a software_statement. The publisher will add an **"iss"** attribute
to the software_statement, that holds a link to the public part of the signing key used to sing the software_statement.
This public key must be hosted from a SSL server with a certificate signed by a trusted certificate authority.


Required attributes in a software_statement
-------------------------------------------

The software_statement need to contain the following attributes:

* **"iss":**
 Holds a link to the public certificate key that will be used to validate the signature of the
 software statement. To be accepted by the OP, the domain of this link need to be present in a list of **trusted domains**
 and the key need to be hosted by a SSL server with a certificate signed by a trusted certificate authority.

* **"redirect_uris":**
 The OP will only accept redirect_uris from the software_statement.


Updating registration settings
------------------------------

Because the software_statement is signed ba a trusted publisher, the RP can update the registration settings in
an authentication step.


Flow
----

#. The RP need to get it's software_statement signed py a trusted publisher. What the RP gets back is a
   signed software_statement jwt containing one additional attribute, the **"iss"**.

#. The RP sends a registration request containing the signed software_statement.

#. When the OP receives a registration requests, the software_statement will be verified. This is done by looking
   at the **"iss"** attribute. First the domain of the given iss link must be present in the **list of trusted domains**.
   Then the hosting server of the public key must be a SSL server with a certificate signed by a trusted certificate authority.
   If these criteria are met, then the public key will be used to validate the signature of the software_statement.

#. If the software_statement is valid, the registration will proceed. Due to performance, the software_statement is cached
   which will prevent a validation in the authentication step.

#. In the authentication step, the RP need to add a software_statement to the authentication request.

#. The OP receives an authentication request containing a software_statement, or else it is rejected. If the given
   software_statement is the same as in the registration, the authentication will proceed. If the software_statement differs
   from the one given in the registration step, a validation of the software_statement will be made as in step 3. If the
   new software_statement is valid, then the RP registration settings will be updated and the authentication proceeds.


Sequence diagram
________________

.. seqdiag::

    seqdiag {
      RP        ->      SSLServer [label = "Software statement (SWS)"];
      RP        <-      SSLServer [label = "Signed JWT"];
      RP        ->      OP [label = "SWS Reg"]
      OP        ->      SSLServer [label = "Get cert.pub key"]
      OP        <-      SSLServer [label = "cert.pub key"]
      OP        ->      OP [label = "verify SWS cert. (Cache SWS)"]
      RP        <-      OP [label = "Reg response"]
      RP        ->      OP [label = "SWS auth"]
      OP        ->      OP [label = "verify SWS cert. (Check cache)"]
      RP        <-      OP [label = "auth resp"]
    }


