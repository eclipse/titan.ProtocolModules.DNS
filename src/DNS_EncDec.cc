/******************************************************************************
* Copyright (c) 2005, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
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
//
//  File:               DNS_EncDec.cc
//  Description:        en/decoding functions for DNS messages
//  Rev:                R7B
//  Prodnr:             CNL 113 429
//

#include "DNS_Types.hh"

///////////////////////////////////////////////////////
// use the following function to decode a DNS message 
// define it in TTCN-3 as:
//
// external function dec_PDU_DNS(in octetstring stream)
//     return PDU_DNS;
//
//PDU__DNS dec__PDU__DNS(const OCTETSTRING& stream);

///////////////////////////////////////////////////////
// use the following function to encode a DNS message 
// define it in TTCN-3 as:
//
// external function enc_PDU_DNS(in PDU_DNS msg,
//     in boolean doCompression,
//     in boolean autoLengthCalc)
//     return octetstring;
//
//OCTETSTRING enc__PDU__DNS(const PDU__DNS& msg,
//                          const BOOLEAN& doCompression,
//                          const BOOLEAN& autoLengthCalc);


#include <string.h>
#include <stdlib.h>

#define DNS_HEADER_SIZE 12

// if defined, logs debug messages while decoding
//#define DNS_DEBUG_DECODING 1

// if defined, logs text representation next to raw messages
#define DNS_LOG_TEXT 1

// if defined, logs PDU_DNS messages before encoding and after decoding
//#define DNS_LOG_MESSAGE 1

// if defined, logs label tree after enconding
//#define DNS_LOG_LABEL_TREE 1

////////////////////////////////////////////////////////////////////////////////
// definitions

namespace DNS__Types {


void dec_DnsHeader(DnsHeader& hdr, const unsigned char *p_stream);

size_t dec_DomainName(const unsigned char *p_stream,
                      const unsigned char *stream_start,
                      int stream_length,
                      CHARSTRING& dest);

const unsigned char *dec_RR(const unsigned char *p_stream,
                            const unsigned char *stream_start,
                            int stream_length,
                            ResourceRecord& dest);

void enc_DnsHeader(const DnsHeader& hdr, unsigned char *p_stream);

// N_CHILDREN_ALLOC_UNIT defines how many pointers are allocated when
// n_children exceeds n_children_alloc.
#define N_CHILDREN_ALLOC_UNIT 4

class label_node {
  char *str;
  size_t len;
  size_t stream_offset;
  size_t n_children;
  size_t n_children_alloc;
  label_node **children;
  label_node *parent;
public:
  label_node(const char *p_str);
  ~label_node();
  // NOTE: *p_child will be deleted by the deconstructor.
  void add_child(label_node *p_child);
  label_node *find_child(const char *str_child) const;
  size_t flush(TTCN_Buffer& buf, bool do_compression);
#ifdef DNS_LOG_LABEL_TREE
  void log(unsigned int log_level = 0) const;
#endif
};

class domain_names {
  label_node root_label;
public:
  domain_names() : root_label(0) { }
  ~domain_names();
  size_t write_domain_name(const char *name, TTCN_Buffer& buf,
      bool do_compression);
};

void enc_RR(TTCN_Buffer& stream, const ResourceRecord& src,
            domain_names& labels, bool do_compression, bool auto_length_calc);

void raw_msg_log(const char *prefix, const unsigned char *p_stream,
                 int stream_length);


////////////////////////////////////////////////////////////////////////////////
// implementation

PDU__DNS dec__PDU__DNS(const OCTETSTRING& stream)
{
  int stream_length = stream.lengthof(), i;
  const unsigned char *p_stream = stream;
  const unsigned char *stream_start = p_stream;
  PDU__DNS msg;

  // log raw message if TTCN_DEBUG logging flag is set
  if(TTCN_Logger::log_this_event(TTCN_DEBUG)) {
    raw_msg_log("Incoming data:", p_stream, stream_length);
  }

  // decode header
  if(stream_length < DNS_HEADER_SIZE) TTCN_error("Error decoding DNS "
    "header. Stream doesn't contain enough octets.");
  dec_DnsHeader(msg.header(), p_stream);
  p_stream += DNS_HEADER_SIZE;

#ifdef DNS_DEBUG_DECODING
    TTCN_Logger::begin_event(TTCN_DEBUG);
    TTCN_Logger::log_event_str("DNS header: ");
    msg.header().log();
    TTCN_Logger::end_event();
#endif

  msg.queries() = NULL_VALUE;
  msg.answers() = NULL_VALUE;
  msg.nameServerRecords() = NULL_VALUE;
  msg.additionalRecords() = NULL_VALUE;

  // decode query resource records
  for(i=0;i<msg.header().qdCount()&&p_stream<stream_start+stream_length; i++) {
    QResourceRecord rec;
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      rec.qName());
    if(p_stream + 4 > stream_start + stream_length)
      TTCN_error("Error decoding query resource record: not enough octets.");
    rec.qType() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;
    rec.qClass() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;
    msg.queries()[i] = rec;
#ifdef DNS_DEBUG_DECODING
      TTCN_Logger::begin_event(TTCN_DEBUG);
      TTCN_Logger::log_event_str("Query resource record: ");
      msg.queries()[i].log();
      TTCN_Logger::end_event();
#endif
  }

  // decode answer resource records
  for(i=0;i<msg.header().anCount()&&p_stream<stream_start+stream_length;i++) {
    ResourceRecord rr;
    p_stream = dec_RR(p_stream, stream_start, stream_length, rr);
#ifdef DNS_DEBUG_DECODING
      TTCN_Logger::begin_event(TTCN_DEBUG);
      TTCN_Logger::log_event_str("Answer resource record: ");
      rr.log();
      TTCN_Logger::end_event();
#endif
    msg.answers()[i] = rr;
  }

  // decode name server resource records
  for(i=0;i<msg.header().nsCount()&&p_stream<stream_start+stream_length;i++) {
    ResourceRecord rr;
    p_stream = dec_RR(p_stream, stream_start, stream_length, rr);
#ifdef DNS_DEBUG_DECODING
      TTCN_Logger::begin_event(TTCN_DEBUG);
      TTCN_Logger::log_event_str("NS resource record: ");
      rr.log();
      TTCN_Logger::end_event();
#endif
    msg.nameServerRecords()[i] = rr;
  }

  // decode additional resource records
  for(i=0;i<msg.header().arCount()&&p_stream<stream_start+stream_length;i++) {
    ResourceRecord rr;
    p_stream = dec_RR(p_stream, stream_start, stream_length, rr);
#ifdef DNS_DEBUG_DECODING
      TTCN_Logger::begin_event(TTCN_DEBUG);
      TTCN_Logger::log_event_str("Additional resource record: ");
      rr.log();
      TTCN_Logger::end_event();
#endif
    msg.additionalRecords()[i] = rr;
  }

#ifdef DNS_LOG_MESSAGE
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event_str("Decoded PDU_DNS: ");
  msg.log();
  TTCN_Logger::end_event();
#endif

  return msg;
}


OCTETSTRING enc__PDU__DNS(const PDU__DNS& msg,
                          const BOOLEAN& doCompression,
                          const BOOLEAN& autoLengthCalc)
{
  TTCN_Buffer stream;
  unsigned char *p_stream = NULL;
  int i;
  domain_names labels;

#ifdef DNS_LOG_MESSAGE
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event_str("Encoding PDU_DNS: ");
  msg.log();
  TTCN_Logger::end_event();
#endif

  if(msg.header().qdCount() != msg.queries().size_of()) TTCN_warning("While "
    "encoding PDU_DNS: `header.qdCount' (%d) differs from size of `queries' "
    "(%d).", (int)msg.header().qdCount(), (int)msg.queries().size_of());
  if(msg.header().anCount() != msg.answers().size_of()) TTCN_warning("While "
    "encoding PDU_DNS: `header.anCount' (%d) differs from size of `answers' "
    "(%d).", (int)msg.header().anCount(), (int)msg.answers().size_of());
  if(msg.header().nsCount() != msg.nameServerRecords().size_of())
    TTCN_warning("While encoding PDU_DNS: `header.nsCount' (%d) differs from "
      "size of `nameServerRecords' (%d).", (int)msg.header().nsCount(),
      (int)msg.nameServerRecords().size_of());
  if(msg.header().arCount() != msg.additionalRecords().size_of())
    TTCN_warning("While encoding PDU_DNS: `header.arCount' (%d) differs from "
      "size of `additionalRecords' (%d).", (int)msg.header().arCount(),
      (int)msg.additionalRecords().size_of());

  // encode header
  size_t stream_end = DNS_HEADER_SIZE;
  stream.get_end(p_stream, stream_end);
  enc_DnsHeader(msg.header(), p_stream);
  stream.increase_length(DNS_HEADER_SIZE);

  // encode query resource records
  for(i = 0; i < msg.queries().size_of(); i++) {
    labels.write_domain_name(msg.queries()[i].qName(), stream,
      doCompression==TRUE);
    stream_end = 4;
    stream.get_end(p_stream, stream_end);
    *p_stream++ = (int)msg.queries()[i].qType() >> 8;
    *p_stream++ = (int)msg.queries()[i].qType() & 0xff;
    *p_stream++ = (int)msg.queries()[i].qClass() >> 8;
    *p_stream = (int)msg.queries()[i].qClass() & 0xff;
    stream.increase_length(4);
  }

  // encode answer resource records
  for(i = 0; i < msg.answers().size_of(); i++) {
    enc_RR(stream, msg.answers()[i], labels, doCompression==TRUE,
      autoLengthCalc==TRUE);
  }

  // encode name server resource records
  for(i = 0; i < msg.nameServerRecords().size_of(); i++) {
    enc_RR(stream, msg.nameServerRecords()[i], labels, doCompression==TRUE,
      autoLengthCalc==TRUE);
  }

  // encode additional resource records
  for(i = 0; i < msg.additionalRecords().size_of(); i++) {
    enc_RR(stream, msg.additionalRecords()[i], labels, doCompression==TRUE,
      autoLengthCalc==TRUE);
  }

  stream.rewind();

  // log raw message if TTCN_DEBUG logging flag is set
  if(TTCN_Logger::log_this_event(TTCN_DEBUG)) {
    raw_msg_log("Outgoing data:", stream.get_data(),
      stream.get_len());
  }

  return OCTETSTRING(stream.get_len(), stream.get_data());
}


///////////////////////////////////
// helper functions for decoding //
///////////////////////////////////

void dec_DnsHeader(DnsHeader& hdr, const unsigned char *p_stream)
{
  hdr.id() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;

  hdr.qr() = ((*p_stream) >> 7) & 0x01;
  hdr.opCode() = ((*p_stream) >> 3) & 0x0f;
  hdr.aa() = ((*p_stream) & 0x04) ? TRUE : FALSE;
  hdr.tc() = ((*p_stream) & 0x02) ? TRUE : FALSE;
  hdr.rd() = ((*p_stream) & 0x01) ? TRUE : FALSE;
  p_stream++;

  hdr.ra() = ((*p_stream) & 0x80) ? TRUE : FALSE;
  unsigned char z = (((*p_stream) & 0x40) >> 6) |
                    (((*p_stream) & 0x20) >> 4) |
                    (((*p_stream) & 0x10) >> 2);
  hdr.z() = BITSTRING(3, &z);
  hdr.rCode() = (*p_stream) & 0x0f;
  p_stream++;

  hdr.qdCount() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;
  hdr.anCount() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;
  hdr.nsCount() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;
  hdr.arCount() = (*p_stream << 8) | *(p_stream+1);
}

// Decompress domain names from stream. Returns the length of the domain name
// ending either at a zero length label or a pointer.
size_t dec_DomainName(const unsigned char *p_stream,
                    const unsigned char *stream_start,
                    int stream_length,
                    CHARSTRING& dest)
{
  size_t ret_val = 0;
  bool ptr_found = false, dest_empty = true;
  char lbl[64]; // labels are max. 63 octets long
  while(true) {
    int len = *p_stream++;
    if(!ptr_found) ret_val++;
    if(len>63) { // pointer
      if(len>>6 != 3) TTCN_error("Error decoding label at octet #%d: label "
        "length is greater than 63, but is not a pointer (0x%02X)",
        (int)(p_stream - stream_start), len);
      len = ((len & 0x3f) << 8) | *p_stream;
      if(!ptr_found) ret_val++;
      ptr_found = true;
      if(len >= stream_length) TTCN_error("Label pointer at octet #%d in "
          "domain name refers after end of stream.",(int)( p_stream - stream_start));
      if(len > p_stream - stream_start) TTCN_warning("Forward reference in "
        "compressed domain name at octet #%d.", (int)(p_stream - stream_start));
      p_stream = stream_start + len;
    } else if(len != 0) {
      if(p_stream + len > stream_start + stream_length)
        TTCN_error("Error decoding label: not enough octets. Remaining bytes: "
          "%d, length of label: %d", (int)(stream_start+stream_length-p_stream), len);
      memcpy(lbl, p_stream, len);
      p_stream += len;
      if(!ptr_found) ret_val += len;
      lbl[len] = '\0';
      if(dest_empty) dest = lbl;
      else {
        dest = dest + ".";
        dest = dest + lbl;
      }
      dest_empty = false;
    } else break;
  }
  if(dest_empty) dest = "";
  return ret_val;
}

// decode a resource record and return a pointer to the next octet
const unsigned char *dec_RR(const unsigned char *p_stream,
                            const unsigned char *stream_start,
                            int stream_length,
                            ResourceRecord& dest)
{
  int rr_start_octet = p_stream - stream_start;
  p_stream += dec_DomainName(p_stream, stream_start, stream_length,
    dest.name());

  // the minimum length of a RR is the length of the domain name plus 10
  if(p_stream - stream_start + 10 > stream_length) TTCN_error("Error decoding "
    "resource record: not enough octets. Resource record starts at octet #%d, "
    "number of octets in message: %d.", rr_start_octet + 1, stream_length);
  dest.rrType() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;
  dest.rrClass() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;
  dest.ttl() = OCTETSTRING(4, p_stream);
  p_stream += 4;
  dest.rdLength() = (*p_stream << 8) | *(p_stream+1);
  p_stream += 2;

  int remaining_octets = stream_length - (p_stream-stream_start);
  const unsigned char *rd_start = p_stream;
  // if there isn't enough octets left then decode to `undecodable'
  if(remaining_octets < (int)dest.rdLength()) {
    TTCN_warning("While decoding resource record: not enough octets, "
      "decoding to field `undecodable'. Resource record starts at octet #%d.",
      rr_start_octet + 1);
    dest.rData().undecodable() = OCTETSTRING(remaining_octets, p_stream);
    return stream_start + stream_length;
  }

  if( (int)dest.rrClass() != 1 && (int)dest.rrClass() != 254  && (int)dest.rrClass() != 255 ) { // RR class is not DNS_IN or DNS_NONE or DNS_ANYCLASS
    TTCN_warning("Resource record class %d is not supported. rData "
        "will be decoded to field `unsupported'.", (int)dest.rrClass());
    dest.rData().unsupported() = OCTETSTRING(remaining_octets, p_stream);
    return rd_start + dest.rdLength();
  }
  
   // RR class is DNS_NONE
  if((dest.rrClass() == 254) && ( (dest.ttl() != int2oct(0,4)) || (dest.rdLength() != 0)) ) {
    TTCN_warning("In case of Resource record class %d rdLength and ttl fields must be zero. rData "
        "will be decoded to field `unsupported'.", (int)dest.rrClass() );   
    dest.rData().unsupported() = OCTETSTRING(remaining_octets, p_stream);
    return rd_start + dest.rdLength();  
  }

  switch((int)dest.rrType()) {
  case 1: // DNS_A
    if(remaining_octets < 4) {
      TTCN_warning("While decoding address resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, p_stream);
      return stream_start + stream_length;
    }
    dest.rData().a() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    break;
  case 2: // DNS_NS
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().ns());
    break;
  case 3: // DNS_MD
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().md());
    break;
  case 4: // DNS_MF
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mf());
    break;
  case 5: // DNS_CNAME
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().cName());
    break;
  case 6: // DNS_SOA
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().soa().mName());
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().soa().rName());
    remaining_octets -= p_stream - rd_start;
    if(remaining_octets < 20) {
      TTCN_warning("While decoding SOA resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    dest.rData().soa().serial() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    dest.rData().soa().refresh() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    dest.rData().soa().retry() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    dest.rData().soa().expire() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    dest.rData().soa().minimum() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    break;
  case 7: // DNS_MB
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mb());
    break;
  case 8: // DNS_MG
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mg());
    break;
  case 9: // DNS_MR
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mr());
    break;
  case 10: // DNS_NULL
    dest.rData().rd__null() = OCTETSTRING(dest.rdLength(), p_stream);
    p_stream += dest.rdLength();
    break;
  case 11: // DNS_WKS
    // minimum size: 5, plus at least one octet for the bitmap
    if(remaining_octets < 6) {
      TTCN_warning("While decoding WKS resource record: not enough octets, "
        "decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    if(dest.rdLength() < 6) {
      TTCN_warning("While decoding WKS resource record: rdLength is less "
        "than 6. Decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING((int)dest.rdLength(), rd_start);
      return rd_start + (int)dest.rdLength();
    }
    dest.rData().wks().addr() = OCTETSTRING(4, p_stream);
    p_stream += 4;
    dest.rData().wks().protocol() = *p_stream++;
    dest.rData().wks().bitmap() = OCTETSTRING(dest.rdLength() - 5, p_stream);
    p_stream += dest.rdLength() - 5;
    break;
  case 12: // DNS_PTR
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().ptr());
    break;
  case 13: { // DNS_HINFO
    if(remaining_octets < 2) { // minimum 2 length octets
      TTCN_warning("While decoding HINFO resource record: not enough octets, "
        "decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    int str_len = *p_stream++;
    remaining_octets--;
    if(remaining_octets < str_len + 1) { // legth of string + 1 length octet
      TTCN_warning("While decoding HINFO resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    dest.rData().hInfo().cpu() = CHARSTRING(str_len, (const char *)p_stream);
    p_stream += str_len;
    str_len = *p_stream++;
    remaining_octets -= str_len + 1;
    if(remaining_octets < str_len) {
      TTCN_warning("While decoding HINFO resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    dest.rData().hInfo().os() = CHARSTRING(str_len, (const char *)p_stream);
    p_stream += str_len;
    break; }
  case 14: // DNS_MINFO
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mInfo().rMailBx());
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mInfo().eMailBx());
    break;
  case 15: // DNS_MX
    if(remaining_octets < 2) {
      TTCN_warning("While decoding MX resource record: not enough octets, "
        "decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    dest.rData().mx().preference() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().mx().exchange());
    break;
  case 16: { // DNS_TXT
    int num_strs=0;
    dest.rData().txt() = NULL_VALUE;
    while(remaining_octets > 0 && p_stream - rd_start < (int)dest.rdLength()) {
      int str_len = *p_stream++;
      remaining_octets--;
      if(remaining_octets == 0) {
        dest.rData().txt()[num_strs++] = CHARSTRING("");
        break;
      } else if(remaining_octets < str_len) {
        dest.rData().txt()[num_strs++] = CHARSTRING(remaining_octets,
          (const char *)p_stream);
        p_stream += remaining_octets;
        remaining_octets = 0;
      } else {
        dest.rData().txt()[num_strs++] = CHARSTRING(str_len,
          (const char *)p_stream);
        p_stream += str_len;
        remaining_octets -= str_len;
      }
    }
    break; }        
  case 28: // DNS_AAAA
    if(remaining_octets < 16) {
      TTCN_warning("While decoding AAAA resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, p_stream);
      return stream_start + stream_length;
    }
    dest.rData().aaaa() = OCTETSTRING(16, p_stream);
    p_stream += 16;
    break;       
  case 33: { // DNS_SRV
    if(remaining_octets < 6) {
      TTCN_warning("While decoding SRV resource record: not enough octets, "
        "decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    dest.rData().srv().priority() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;
    dest.rData().srv().weight() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;
    dest.rData().srv().portnum() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;    
    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().srv().target());
    break; }
  case 35: { // DNS_NAPTR
    if(remaining_octets < 4) {
      TTCN_warning("While decoding NAPTR resource record: not enough octets, "
        "decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }

    dest.rData().naptr().order() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;
    dest.rData().naptr().preference() = (*p_stream << 8) | *(p_stream+1);
    p_stream += 2;

    if(remaining_octets < 3) { // minimum 3 length octets
      TTCN_warning("While decoding NAPTR resource record: not enough octets, "
        "decoding to field `undecodable'.");
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    
    int str_len = *p_stream++;

    remaining_octets -= 4;
    if(remaining_octets < str_len + 3) { // length of string + 3 length octet
      TTCN_warning("While decoding NAPTR resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    
    dest.rData().naptr().flags() = CHARSTRING(str_len, (const char *)p_stream);
    p_stream += str_len;
    remaining_octets -= str_len + 1;
    str_len = *p_stream++;
    if(remaining_octets < str_len + 2) {
      TTCN_warning("While decoding NAPTR resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    
    dest.rData().naptr().services() = CHARSTRING(str_len, (const char *)p_stream);
    p_stream += str_len;   
    remaining_octets -= str_len + 1;

    str_len = *p_stream++;
    if(remaining_octets < str_len + 1) {
      TTCN_warning("While decoding NAPTR resource record: not enough octets, "
        "decoding to field `undecodable'.");
      remaining_octets = stream_length - (rd_start-stream_start);
      dest.rData().undecodable() = OCTETSTRING(remaining_octets, rd_start);
      return stream_start + stream_length;
    }
    
    dest.rData().naptr().regexpString() = CHARSTRING(str_len, (const char *)p_stream);
    p_stream += str_len;   
    remaining_octets -= str_len + 1;

    p_stream += dec_DomainName(p_stream, stream_start, stream_length,
      dest.rData().naptr().replacement());

    break; } 
  case 255: {// DNS_ALLRECORDS (ANY type)
    
      dest.rData().rd__null() = OCTETSTRING((int)dest.rdLength(), p_stream);
      return rd_start + (int)dest.rdLength();
       
    break;  }
  default:
    TTCN_warning("Resource record type %d is not supported. rData will be "
      "decoded to field `unsupported'.", (int)dest.rrType());
    dest.rData().unsupported() = OCTETSTRING((int)dest.rdLength(), p_stream);
    return rd_start + (int)dest.rdLength();
  }
  if((int)dest.rdLength() != p_stream - rd_start) TTCN_warning("While decoding "
    "resource record: rdLength (%d) does not equal the length of decoded "
    "resource record data (%d). Resource record starts at octet #%d.",
    (int)dest.rdLength(), (int)(p_stream-rd_start), rr_start_octet + 1);
  return p_stream;
}

///////////////////////////////////
// helper functions for encoding //
///////////////////////////////////

void enc_DnsHeader(const DnsHeader& hdr, unsigned char *p_stream)
{
  int i;
  i = hdr.id();
  *p_stream++=i >> 8;
  *p_stream++=i & 0xff;

  *p_stream = ((int)hdr.opCode() << 3) & 0x78;
  if((QueryOrResponse::enum_type)hdr.qr() == 1) *p_stream |= 0x80; // DNS_RESPONSE
  if(hdr.aa() == TRUE) *p_stream |= 0x04;
  if(hdr.tc() == TRUE) *p_stream |= 0x02;
  if(hdr.rd() == TRUE) *p_stream |= 0x01;
  p_stream++;

  *p_stream = (int)hdr.rCode() & 0x0f;
  if(hdr.ra() == TRUE) *p_stream |= 0x80;
  if(hdr.z().lengthof() != 3) TTCN_error("Error encoding DNS header: field `z' "
    "must have a length of 3.");
  const unsigned char *z = hdr.z();
  if(z == NULL) TTCN_error("Error encoding DNS header: field `z' is empty");
  if(*z & 0x01) *p_stream |= 0x40;
  if(*z & 0x02) *p_stream |= 0x20;
  if(*z & 0x04) *p_stream |= 0x10;
  p_stream++;

  i = hdr.qdCount();
  *p_stream++=i >> 8;
  *p_stream++=i & 0xff;

  i = hdr.anCount();
  *p_stream++=i >> 8;
  *p_stream++=i & 0xff;

  i = hdr.nsCount();
  *p_stream++=i >> 8;
  *p_stream++=i & 0xff;

  i = hdr.arCount();
  *p_stream++=i >> 8;
  *p_stream++=i & 0xff;
}

// encode a resource record
void enc_RR(TTCN_Buffer& stream, const ResourceRecord& src,
            domain_names& labels, bool do_compression, bool auto_length_calc)
{
  unsigned char *p_stream;
  int rdLength=0;
  labels.write_domain_name(src.name(), stream, do_compression);

  size_t stream_end = 4;
  stream.get_end(p_stream, stream_end);
  *p_stream++ = (int)src.rrType() >> 8;
  *p_stream++ = (int)src.rrType() & 0xff;
  *p_stream++ = (int)src.rrClass() >> 8;
  *p_stream++ = (int)src.rrClass() & 0xff;
  stream.increase_length(4);

  stream.put_os(src.ttl());
  p_stream += 4; // UInt32

  unsigned char *p_rdLength = p_stream;
  stream.put_c((int)src.rdLength() >> 8);
  stream.put_c((int)src.rdLength() & 0xff);

  switch(src.rData().get_selection()) {
  case ResourceData::ALT_cName:
    rdLength = labels.write_domain_name(src.rData().cName(), stream,
      do_compression);
    break;
  case ResourceData::ALT_hInfo: {
    size_t cpu_length = src.rData().hInfo().cpu().lengthof();
    size_t os_length = src.rData().hInfo().os().lengthof();
    stream_end = cpu_length + os_length + 2;
    stream.get_end(p_stream, stream_end);
    *p_stream++ = cpu_length;
    memcpy(p_stream, (const char*)src.rData().hInfo().cpu(), cpu_length);
    p_stream += cpu_length;
    *p_stream++ = os_length;
    memcpy(p_stream, (const char*)src.rData().hInfo().os(), os_length);
    rdLength = cpu_length + os_length + 2;
    stream.increase_length(rdLength);
    break; }
  case ResourceData::ALT_mb:
    rdLength = labels.write_domain_name(src.rData().mb(), stream,
      do_compression);
    break;
  case ResourceData::ALT_md:
    rdLength = labels.write_domain_name(src.rData().md(), stream,
      do_compression);
    break;
  case ResourceData::ALT_mf:
    rdLength = labels.write_domain_name(src.rData().mf(), stream,
      do_compression);
    break;
  case ResourceData::ALT_mg:
    rdLength = labels.write_domain_name(src.rData().mg(), stream,
      do_compression);
    break;
  case ResourceData::ALT_mInfo:
    rdLength = labels.write_domain_name(src.rData().mInfo().rMailBx(), stream,
      do_compression);
    rdLength += labels.write_domain_name(src.rData().mInfo().eMailBx(), stream,
      do_compression);
    break;
  case ResourceData::ALT_mr:
    rdLength = labels.write_domain_name(src.rData().mr(), stream,
      do_compression);
    break;
  case ResourceData::ALT_mx:
    stream.put_c((int)src.rData().mx().preference() >> 8);
    stream.put_c((int)src.rData().mx().preference() & 0xff);
    rdLength = 2;
    rdLength += labels.write_domain_name(src.rData().mx().exchange(), stream,
      do_compression);
    break;
  case ResourceData::ALT_rd__null:
    stream.put_os(src.rData().rd__null());
    rdLength = src.rData().rd__null().lengthof();
    break;
  case ResourceData::ALT_ns:
    rdLength = labels.write_domain_name(src.rData().ns(), stream,
      do_compression);
    break;
  case ResourceData::ALT_ptr:
    rdLength = labels.write_domain_name(src.rData().ptr(), stream,
      do_compression);
    break;
  case ResourceData::ALT_soa:
    rdLength = labels.write_domain_name(src.rData().soa().mName(), stream,
      do_compression);
    rdLength += labels.write_domain_name(src.rData().soa().rName(), stream,
      do_compression);
    stream.put_os(src.rData().soa().serial());
    stream.put_os(src.rData().soa().refresh());
    stream.put_os(src.rData().soa().retry());
    stream.put_os(src.rData().soa().expire());
    stream.put_os(src.rData().soa().minimum());
    rdLength += 20; // 5*UInt32
    break;
  case ResourceData::ALT_txt:
    for(int i=0; i<src.rData().txt().size_of(); i++) {
      int txtlen = src.rData().txt()[i].lengthof();
      stream_end = txtlen + 1;
      stream.get_end(p_stream, stream_end);
      *p_stream++ = txtlen;
      memcpy(p_stream, (const char*)src.rData().txt()[i], txtlen);
      stream.increase_length(txtlen + 1);
      rdLength += txtlen + 1;
    }
    break;
  case ResourceData::ALT_a:
    stream.put_os(src.rData().a());
    rdLength = 4; // UInt32
    break;
  case ResourceData::ALT_wks:
    stream.put_os(src.rData().wks().addr());
    stream.put_c(src.rData().wks().protocol());
    stream.put_os(src.rData().wks().bitmap());
    rdLength = src.rData().wks().bitmap().lengthof() + 5; // UInt32 + UInt8
    break;
  case ResourceData::ALT_srv:
    stream.put_c((int)src.rData().srv().priority() >> 8);
    stream.put_c((int)src.rData().srv().priority() & 0xff);
    rdLength = 2;
    stream.put_c((int)src.rData().srv().weight() >> 8);
    stream.put_c((int)src.rData().srv().weight() & 0xff);
    rdLength += 2;
    stream.put_c((int)src.rData().srv().portnum() >> 8);
    stream.put_c((int)src.rData().srv().portnum() & 0xff);
    rdLength += 2;
    rdLength += labels.write_domain_name(src.rData().srv().target(), stream,
      do_compression);
    break;
  case ResourceData::ALT_naptr: {
    stream.put_c((int)src.rData().naptr().order() >> 8);
    stream.put_c((int)src.rData().naptr().order() & 0xff);
    rdLength = 2;
    stream.put_c((int)src.rData().naptr().preference() >> 8);
    stream.put_c((int)src.rData().naptr().preference() & 0xff);
    rdLength += 2;
    
    size_t flags_length = src.rData().naptr().flags().lengthof();
    size_t services_length = src.rData().naptr().services().lengthof();
    size_t regexpString_length = src.rData().naptr().regexpString().lengthof();
    
    stream_end = flags_length + services_length + regexpString_length;
    stream.get_end(p_stream, stream_end);

    *p_stream++ = flags_length;
    memcpy(p_stream, (const char*)src.rData().naptr().flags(), flags_length);
    p_stream += flags_length;

    *p_stream++ = services_length;
    memcpy(p_stream, (const char*)src.rData().naptr().services(), services_length);
    p_stream += services_length;

    *p_stream++ = regexpString_length;
    memcpy(p_stream, (const char*)src.rData().naptr().regexpString(), regexpString_length);
    p_stream += regexpString_length;

    rdLength += flags_length + services_length + regexpString_length - 1;
    stream.increase_length(rdLength);
    
    rdLength += labels.write_domain_name(src.rData().naptr().replacement(), stream, do_compression) + 4;

    break; }
  case ResourceData::ALT_aaaa:
    stream.put_os(src.rData().aaaa());
    rdLength = 16;
    break;     
  case ResourceData::ALT_unsupported:
    stream.put_os(src.rData().unsupported());
    rdLength = src.rData().unsupported().lengthof();
    break;
  case ResourceData::ALT_undecodable:
    stream.put_os(src.rData().undecodable());
    rdLength = src.rData().undecodable().lengthof();
    break;
  default:
    TTCN_error("Error encoding resource data: undefined union selection.");
    break;
  }
  if(auto_length_calc) {
    *p_rdLength++ = rdLength >> 8;
    *p_rdLength = rdLength & 0xff;
  } else if(src.rdLength() != rdLength) {
    TTCN_Logger::begin_event(TTCN_WARNING);
    TTCN_Logger::log_event("Length of rData (%d) in octets differs from "
      "rdLength (%d) in resource record: ", rdLength, (int)src.rdLength());
    src.log();
    TTCN_Logger::end_event();
  }
}


// function for logging octets in en/decoded messages
void raw_msg_log(const char *prefix, const unsigned char *p_stream,
                 int stream_length)
{
#ifdef DNS_LOG_TEXT
  char txtlog[24];
  int i, txtlog_i;
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event_str(prefix);
  for(i = 0, txtlog_i = 0; i < stream_length; i++) {
    if(i%16==0){ 
      txtlog[txtlog_i]='\0';
      TTCN_Logger::log_event("  %s\n", txtlog);
      txtlog[0]='\0';
      txtlog_i=0;
    }
    if(i%8==0) {
      TTCN_Logger::log_event_str("  ");
      txtlog[txtlog_i++]=' ';
    }
    TTCN_Logger::log_event(" %02x", p_stream[i]);
    if(p_stream[i]>31 && p_stream[i]<127)txtlog[txtlog_i++]=p_stream[i];
    else txtlog[txtlog_i++]='.';
  }
  if(txtlog[0]!='\0') {
    txtlog[txtlog_i]='\0';
    i--;
    // right-justify logged text
    for(txtlog_i=i%16;txtlog_i<15;txtlog_i++)TTCN_Logger::log_event_str("   ");
    if((i%16)<8)TTCN_Logger::log_event_str("  ");
    TTCN_Logger::log_event("  %s", txtlog);
  }
  TTCN_Logger::log_event("\n");
  TTCN_Logger::end_event();
#else
// simpler but less useful
  int i;
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event_str(prefix);
  for(i = 0; i < stream_length; i++) {
    if(i%16==0) TTCN_Logger::log_event_str("\n");
    if(i%8==0)  TTCN_Logger::log_event_str("  ");
    TTCN_Logger::log_event(" %02x", p_stream[i]);
  }
  TTCN_Logger::log_event("\n");
  TTCN_Logger::end_event();
#endif
}


//////////////////////
// class label_node //
//////////////////////

label_node::label_node(const char *p_str)
    : str(NULL), len(0), stream_offset(0), n_children(0), n_children_alloc(0),
    children(NULL), parent(NULL)
{
  if(p_str) {
    len = strlen(p_str);
    if(len>63) TTCN_error("Label is longer than 63 characters: \"%s\"", p_str);
    str = new char[len + 1];
    strcpy(str, p_str);
  }
}

label_node::~label_node()
{
  if(str) delete []str;
  for(size_t i=0; i<n_children; i++) delete children[i];
  free(children);
}

// add a child node (leaf) to tree
void label_node::add_child(label_node *p_child)
{
  if(!p_child) TTCN_error("label_node::add_child(): NULL pointer");
  if(!p_child->str) TTCN_error("label_node::add_child(): root label");
  p_child->parent = this;
  n_children++;
  if(n_children_alloc < n_children) {
    n_children_alloc += N_CHILDREN_ALLOC_UNIT;
    if(children) children = (label_node**)realloc(children,
      n_children_alloc * sizeof(label_node*));
    else children = (label_node**)malloc(N_CHILDREN_ALLOC_UNIT *
      sizeof(label_node*));
    if(!children) TTCN_error("label_node::add_child(): memory allocation error.");
  }
  children[n_children-1] = p_child;
}

// return the child which has the string str_child or NULL if not found
label_node *label_node::find_child(const char *str_child) const
{
  // Implementation of a more efficient search alorithm might decrese
  // performance with small data sets (which we will encounter within one DNS
  // message) because of the increased complexity.
  for(size_t i=0; i<n_children; i++) if(!strcmp(children[i]->str, str_child))
    return children[i];
  return NULL;
}

// write domain name (labels+0 or labels+pointer) to output stream
// returns the number of bytes written to buf
size_t label_node::flush(TTCN_Buffer& buf, bool do_compression)
{
  if(!str) {
    buf.put_c(0); // root label is the last label
    return 1;
  } else if(stream_offset!=0 && do_compression) {
    // stream_offset != 0 --> label already written to buffer, write a ptr to it
    buf.put_c((stream_offset >> 8) | 0xc0);
    buf.put_c(stream_offset & 0xff);
    return 2;
  } else {
    stream_offset = buf.get_len();
    buf.put_c(len);
    buf.put_s(len, (const unsigned char*)str);
    if(parent) return len + 1 + parent->flush(buf, do_compression);
    else return len + 1;
  }
}

#ifdef DNS_LOG_LABEL_TREE

void label_node::log(unsigned int log_level) const
{
  unsigned int i;
  if(!str) {
    TTCN_Logger::log_event_str("\nroot_label\n");
  } else {
    for(i=0;i<log_level-1;i++)TTCN_Logger::log_event_str(" |  ");
    if(str)TTCN_Logger::log_event(" |->\"%s\"\n",str);
  }
  for(i=0;i<n_children;i++)children[i]->log(log_level + 1);
}

#endif // DNS_LOG_LABEL_TREE

////////////////////////
// class domain_names //
////////////////////////

domain_names::~domain_names()
{
#ifdef DNS_LOG_LABEL_TREE
  TTCN_Logger::begin_event(TTCN_DEBUG);
  TTCN_Logger::log_event_str("Label tree after encoding:\n");
  root_label.log();
  TTCN_Logger::end_event();
#endif
}

// write a domain name to output stream and update label-tree used by the
// domain name compression algorithm
// returns the number of bytes written to buf
size_t domain_names::write_domain_name(const char *name, TTCN_Buffer& buf,
    bool do_compression)
{
  if(name==NULL || *name=='\0') {
    TTCN_warning("While encoding domain name: domain name is empty.");
    buf.put_c(0);
    return 1;
  }
  const char *end_p = name + strlen(name) - 1;

  // Domain name should not start or end with a dot.
  if(*name=='.') TTCN_error("Domain name should not start with a dot: \"%s\".",
    name);
  if(*end_p=='.') TTCN_error("Domain name should not end with a dot: \"%s\".",
    name);

  char lbl[64];
  int lbl_len=0;
  label_node *leaf = &root_label;

  // `nothing_new' is false until there's no new labels detected in `name'
  // while comparing labels of name begining from root label in tree.
  // Set to false once a new label is added to the tree. Once it's false,
  // subsequent labels of `name' should be added to the branch without matching.
  bool nothing_new = true;

  // Get labels from end of name, and match them with labels stored in tree,
  // starting at root, on one branch. Add labels (and stop matching) once a
  // new label is encountered.
  do {
    if(end_p == name || *end_p == '.') { // reached start of label
      if(end_p!=name) {
        if(lbl_len == 0) continue; // Avoids multiple dots. end_p-- in loop condition
        memcpy(lbl, end_p + 1, lbl_len);
        lbl[lbl_len] = '\0';
      } else {
        lbl_len++;
        memcpy(lbl, end_p, lbl_len);
        lbl[lbl_len] = '\0';
      }

      if(nothing_new) { // no new label in this domain name (yet)
        label_node *child = leaf->find_child(lbl);
        if(child!=NULL) { // label is already in tree
          leaf = child;
        } else { // New label, add to tree.
          nothing_new = false; // more compression for this name is not possible
          label_node *new_node = new label_node(lbl);
          leaf->add_child(new_node);
          leaf = new_node;
        }
      } else { 
        // there was a new label already, don't try to search for current one,
        // just add it to tree (to leaf).
        label_node *new_node = new label_node(lbl);
        leaf->add_child(new_node);
        leaf = new_node;
      }

      lbl_len = 0;
    } else {
      lbl_len++;
      if(lbl_len>63) TTCN_error("Label in domain name is longer than 63 "
        "characters: \"%s\"", name);
    }
  } while(end_p-- > name);

  // write branch into the buffer, starting at leaf
  return leaf->flush(buf, do_compression);
}

}//namespace

