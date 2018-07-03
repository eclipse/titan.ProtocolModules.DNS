/******************************************************************************
* Copyright (c) 2005, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
*   Gabor Tatarka - initial implementation and initial documentation
*   Attila Balasko
*   Attila Fulop
*   Endre Kulcsar
*   Gabor Szalai
*   Mate Csorba
*   Sandor Palugyai
*   Tibor Csondes
******************************************************************************/

The demo opens a UDP port (configured in config.cfg) and waits for incoming
DNS messages. If it receives a DNS pointer or address query and the
query is defined in the demo module then it replies with a DNS answer,
otherwise with a DNS name error.

The demo testcase automatically exits if it doesn't receive any messages for
30 seconds.

You can send DNS queries to the demo testcase using the following command
in a unix/linux shell (assuming the demo runs on the same host):

    nslookup -port=<port_number> <domain_name> localhost

where port_number is the UDP port number set in config.cfg and domain_name
is one of the predefined domain names in DNS_Demo.ttcn (see definition of
cg_addrAssignments).
