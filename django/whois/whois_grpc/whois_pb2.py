# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: whois.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0bwhois.proto\x12\x05whois\"\x1d\n\x0cWHOISRequest\x12\r\n\x05query\x18\x01 \x01(\t\"\x95\x01\n\nWHOISReply\x12)\n\x07objects\x18\x01 \x03(\x0b\x32\x18.whois.WHOISReply.Object\x1a%\n\x07\x45lement\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\x1a\x35\n\x06Object\x12+\n\x08\x65lements\x18\x01 \x03(\x0b\x32\x19.whois.WHOISReply.Element2?\n\x05WHOIS\x12\x36\n\nWHOISQuery\x12\x13.whois.WHOISRequest\x1a\x11.whois.WHOISReply\"\x00\x62\x06proto3')



_WHOISREQUEST = DESCRIPTOR.message_types_by_name['WHOISRequest']
_WHOISREPLY = DESCRIPTOR.message_types_by_name['WHOISReply']
_WHOISREPLY_ELEMENT = _WHOISREPLY.nested_types_by_name['Element']
_WHOISREPLY_OBJECT = _WHOISREPLY.nested_types_by_name['Object']
WHOISRequest = _reflection.GeneratedProtocolMessageType('WHOISRequest', (_message.Message,), {
  'DESCRIPTOR' : _WHOISREQUEST,
  '__module__' : 'whois_pb2'
  # @@protoc_insertion_point(class_scope:whois.WHOISRequest)
  })
_sym_db.RegisterMessage(WHOISRequest)

WHOISReply = _reflection.GeneratedProtocolMessageType('WHOISReply', (_message.Message,), {

  'Element' : _reflection.GeneratedProtocolMessageType('Element', (_message.Message,), {
    'DESCRIPTOR' : _WHOISREPLY_ELEMENT,
    '__module__' : 'whois_pb2'
    # @@protoc_insertion_point(class_scope:whois.WHOISReply.Element)
    })
  ,

  'Object' : _reflection.GeneratedProtocolMessageType('Object', (_message.Message,), {
    'DESCRIPTOR' : _WHOISREPLY_OBJECT,
    '__module__' : 'whois_pb2'
    # @@protoc_insertion_point(class_scope:whois.WHOISReply.Object)
    })
  ,
  'DESCRIPTOR' : _WHOISREPLY,
  '__module__' : 'whois_pb2'
  # @@protoc_insertion_point(class_scope:whois.WHOISReply)
  })
_sym_db.RegisterMessage(WHOISReply)
_sym_db.RegisterMessage(WHOISReply.Element)
_sym_db.RegisterMessage(WHOISReply.Object)

_WHOIS = DESCRIPTOR.services_by_name['WHOIS']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _WHOISREQUEST._serialized_start=22
  _WHOISREQUEST._serialized_end=51
  _WHOISREPLY._serialized_start=54
  _WHOISREPLY._serialized_end=203
  _WHOISREPLY_ELEMENT._serialized_start=111
  _WHOISREPLY_ELEMENT._serialized_end=148
  _WHOISREPLY_OBJECT._serialized_start=150
  _WHOISREPLY_OBJECT._serialized_end=203
  _WHOIS._serialized_start=205
  _WHOIS._serialized_end=268
# @@protoc_insertion_point(module_scope)
