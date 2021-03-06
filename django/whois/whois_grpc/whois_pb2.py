# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: whois.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='whois.proto',
  package='whois',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\x0bwhois.proto\x12\x05whois\"\x1d\n\x0cWHOISRequest\x12\r\n\x05query\x18\x01 \x01(\t\"\x95\x01\n\nWHOISReply\x12)\n\x07objects\x18\x01 \x03(\x0b\x32\x18.whois.WHOISReply.Object\x1a%\n\x07\x45lement\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\x1a\x35\n\x06Object\x12+\n\x08\x65lements\x18\x01 \x03(\x0b\x32\x19.whois.WHOISReply.Element2?\n\x05WHOIS\x12\x36\n\nWHOISQuery\x12\x13.whois.WHOISRequest\x1a\x11.whois.WHOISReply\"\x00\x62\x06proto3'
)




_WHOISREQUEST = _descriptor.Descriptor(
  name='WHOISRequest',
  full_name='whois.WHOISRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='query', full_name='whois.WHOISRequest.query', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=22,
  serialized_end=51,
)


_WHOISREPLY_ELEMENT = _descriptor.Descriptor(
  name='Element',
  full_name='whois.WHOISReply.Element',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='whois.WHOISReply.Element.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='whois.WHOISReply.Element.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=111,
  serialized_end=148,
)

_WHOISREPLY_OBJECT = _descriptor.Descriptor(
  name='Object',
  full_name='whois.WHOISReply.Object',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='elements', full_name='whois.WHOISReply.Object.elements', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=150,
  serialized_end=203,
)

_WHOISREPLY = _descriptor.Descriptor(
  name='WHOISReply',
  full_name='whois.WHOISReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='objects', full_name='whois.WHOISReply.objects', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_WHOISREPLY_ELEMENT, _WHOISREPLY_OBJECT, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=54,
  serialized_end=203,
)

_WHOISREPLY_ELEMENT.containing_type = _WHOISREPLY
_WHOISREPLY_OBJECT.fields_by_name['elements'].message_type = _WHOISREPLY_ELEMENT
_WHOISREPLY_OBJECT.containing_type = _WHOISREPLY
_WHOISREPLY.fields_by_name['objects'].message_type = _WHOISREPLY_OBJECT
DESCRIPTOR.message_types_by_name['WHOISRequest'] = _WHOISREQUEST
DESCRIPTOR.message_types_by_name['WHOISReply'] = _WHOISREPLY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

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



_WHOIS = _descriptor.ServiceDescriptor(
  name='WHOIS',
  full_name='whois.WHOIS',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=205,
  serialized_end=268,
  methods=[
  _descriptor.MethodDescriptor(
    name='WHOISQuery',
    full_name='whois.WHOIS.WHOISQuery',
    index=0,
    containing_service=None,
    input_type=_WHOISREQUEST,
    output_type=_WHOISREPLY,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_WHOIS)

DESCRIPTOR.services_by_name['WHOIS'] = _WHOIS

# @@protoc_insertion_point(module_scope)
