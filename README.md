# AutoStealer

## Summary

This repository contains a proof of concept for an Unauthorized Sign Attack using the @Firma application. If @Firma is launched with the given parameters, the script can then use the JDB debugger to intercept and modify some of the function calls performed during the signing process. This tools allows for automatic recovery of the PIN used to authenticate the user to the Spanish eID and then launches a second @Firma process which then signs a given document without almost any noticeable indication to the user.

## Article

This code is part of an ongoing study contained in the following article:

- Un estudio del DNIe y de su infraestructura
- Javier Correa-Marichal, Pino Caballero-Gil, Carlos Rosa-Remedios, Rames Sarwat-Shaker
- Pending publication. Repository will be updated once it is publicly availble.

The National Identity Document is a fundamental piece of documentation for the identification of citizens throughout the world. That is precisely the case of the DNI (Documento Nacional de Identidad) of Spain. Its importance has been enhanced in recent years with the addition of a chip for the authentication of users within telematic administrative services. Thus, the document has since been called: electronic DNI or simply DNIe. Sensitive user information is stored in that integrated circuit, such as personal and biometric data, along with signature and authentication certificates. Some of the functionalities of the DNIe in its current version at the time of writing this work have been implemented for years in the DNI 3.0 version launched in 2015, and therefore have already been extensively studied. This work provides a theoretical and practical compilation study of some of the security mechanisms included in the current DNIe and in some of the applications that require its use. It has been carried out using only mobile devices and generic card readers, without having any type of privileged access to hardware, software or specific documentation for the interception of packets between the DNIe and the destination application. In other words, it is an exploratory analysis carried out with the intention of confirming with basic tools the level of robustness of this very important security token.
