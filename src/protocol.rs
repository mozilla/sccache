// This file is generated. Do not edit
// @generated

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_imports)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(Clone,Default)]
pub struct GetStats {
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for GetStats {}

impl GetStats {
    pub fn new() -> GetStats {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static GetStats {
        static mut instance: ::protobuf::lazy::Lazy<GetStats> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const GetStats,
        };
        unsafe {
            instance.get(|| {
                GetStats {
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }
}

impl ::protobuf::Message for GetStats {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<GetStats>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for GetStats {
    fn new() -> GetStats {
        GetStats::new()
    }

    fn descriptor_static(_: ::std::option::Option<GetStats>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let fields = ::std::vec::Vec::new();
                ::protobuf::reflect::MessageDescriptor::new::<GetStats>(
                    "GetStats",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for GetStats {
    fn clear(&mut self) {
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for GetStats {
    fn eq(&self, other: &GetStats) -> bool {
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for GetStats {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct Shutdown {
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for Shutdown {}

impl Shutdown {
    pub fn new() -> Shutdown {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static Shutdown {
        static mut instance: ::protobuf::lazy::Lazy<Shutdown> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Shutdown,
        };
        unsafe {
            instance.get(|| {
                Shutdown {
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }
}

impl ::protobuf::Message for Shutdown {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<Shutdown>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for Shutdown {
    fn new() -> Shutdown {
        Shutdown::new()
    }

    fn descriptor_static(_: ::std::option::Option<Shutdown>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let fields = ::std::vec::Vec::new();
                ::protobuf::reflect::MessageDescriptor::new::<Shutdown>(
                    "Shutdown",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for Shutdown {
    fn clear(&mut self) {
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for Shutdown {
    fn eq(&self, other: &Shutdown) -> bool {
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct Compile {
    // message fields
    cwd: ::protobuf::SingularField<::std::string::String>,
    command: ::protobuf::RepeatedField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for Compile {}

impl Compile {
    pub fn new() -> Compile {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static Compile {
        static mut instance: ::protobuf::lazy::Lazy<Compile> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Compile,
        };
        unsafe {
            instance.get(|| {
                Compile {
                    cwd: ::protobuf::SingularField::none(),
                    command: ::protobuf::RepeatedField::new(),
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // required string cwd = 1;

    pub fn clear_cwd(&mut self) {
        self.cwd.clear();
    }

    pub fn has_cwd(&self) -> bool {
        self.cwd.is_some()
    }

    // Param is passed by value, moved
    pub fn set_cwd(&mut self, v: ::std::string::String) {
        self.cwd = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_cwd<'a>(&'a mut self) -> &'a mut ::std::string::String {
        if self.cwd.is_none() {
            self.cwd.set_default();
        };
        self.cwd.as_mut().unwrap()
    }

    // Take field
    pub fn take_cwd(&mut self) -> ::std::string::String {
        self.cwd.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_cwd<'a>(&'a self) -> &'a str {
        match self.cwd.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    // repeated string command = 2;

    pub fn clear_command(&mut self) {
        self.command.clear();
    }

    // Param is passed by value, moved
    pub fn set_command(&mut self, v: ::protobuf::RepeatedField<::std::string::String>) {
        self.command = v;
    }

    // Mutable pointer to the field.
    pub fn mut_command<'a>(&'a mut self) -> &'a mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.command
    }

    // Take field
    pub fn take_command(&mut self) -> ::protobuf::RepeatedField<::std::string::String> {
        ::std::mem::replace(&mut self.command, ::protobuf::RepeatedField::new())
    }

    pub fn get_command<'a>(&'a self) -> &'a [::std::string::String] {
        &self.command
    }
}

impl ::protobuf::Message for Compile {
    fn is_initialized(&self) -> bool {
        if self.cwd.is_none() {
            return false;
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    try!(::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.cwd));
                },
                2 => {
                    try!(::protobuf::rt::read_repeated_string_into(wire_type, is, &mut self.command));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in self.cwd.iter() {
            my_size += ::protobuf::rt::string_size(1, &value);
        };
        for value in self.command.iter() {
            my_size += ::protobuf::rt::string_size(2, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.cwd.as_ref() {
            try!(os.write_string(1, &v));
        };
        for v in self.command.iter() {
            try!(os.write_string(2, &v));
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<Compile>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for Compile {
    fn new() -> Compile {
        Compile::new()
    }

    fn descriptor_static(_: ::std::option::Option<Compile>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_string_accessor(
                    "cwd",
                    Compile::has_cwd,
                    Compile::get_cwd,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_string_accessor(
                    "command",
                    Compile::get_command,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Compile>(
                    "Compile",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for Compile {
    fn clear(&mut self) {
        self.clear_cwd();
        self.clear_command();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for Compile {
    fn eq(&self, other: &Compile) -> bool {
        self.cwd == other.cwd &&
        self.command == other.command &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for Compile {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct ClientRequest {
    // message oneof groups
    request: ::std::option::Option<ClientRequest_oneof_request>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ClientRequest {}

#[derive(Clone,PartialEq)]
pub enum ClientRequest_oneof_request {
    get_stats(GetStats),
    shutdown(Shutdown),
    compile(Compile),
}

impl ClientRequest {
    pub fn new() -> ClientRequest {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ClientRequest {
        static mut instance: ::protobuf::lazy::Lazy<ClientRequest> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ClientRequest,
        };
        unsafe {
            instance.get(|| {
                ClientRequest {
                    request: ::std::option::Option::None,
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // optional .sccache.GetStats get_stats = 1;

    pub fn clear_get_stats(&mut self) {
        self.request = ::std::option::Option::None;
    }

    pub fn has_get_stats(&self) -> bool {
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_get_stats(&mut self, v: GetStats) {
        self.request = ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_get_stats<'a>(&'a mut self) -> &'a mut GetStats {
        if let ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(_)) = self.request {
        } else {
            self.request = ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(GetStats::new()));
        }
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_get_stats(&mut self) -> GetStats {
        if self.has_get_stats() {
            match self.request.take() {
                ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(v)) => v,
                _ => panic!(),
            }
        } else {
            GetStats::new()
        }
    }

    pub fn get_get_stats<'a>(&'a self) -> &'a GetStats {
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(ref v)) => v,
            _ => GetStats::default_instance(),
        }
    }

    // optional .sccache.Shutdown shutdown = 2;

    pub fn clear_shutdown(&mut self) {
        self.request = ::std::option::Option::None;
    }

    pub fn has_shutdown(&self) -> bool {
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_shutdown(&mut self, v: Shutdown) {
        self.request = ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_shutdown<'a>(&'a mut self) -> &'a mut Shutdown {
        if let ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(_)) = self.request {
        } else {
            self.request = ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(Shutdown::new()));
        }
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_shutdown(&mut self) -> Shutdown {
        if self.has_shutdown() {
            match self.request.take() {
                ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(v)) => v,
                _ => panic!(),
            }
        } else {
            Shutdown::new()
        }
    }

    pub fn get_shutdown<'a>(&'a self) -> &'a Shutdown {
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(ref v)) => v,
            _ => Shutdown::default_instance(),
        }
    }

    // optional .sccache.Compile compile = 3;

    pub fn clear_compile(&mut self) {
        self.request = ::std::option::Option::None;
    }

    pub fn has_compile(&self) -> bool {
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::compile(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_compile(&mut self, v: Compile) {
        self.request = ::std::option::Option::Some(ClientRequest_oneof_request::compile(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_compile<'a>(&'a mut self) -> &'a mut Compile {
        if let ::std::option::Option::Some(ClientRequest_oneof_request::compile(_)) = self.request {
        } else {
            self.request = ::std::option::Option::Some(ClientRequest_oneof_request::compile(Compile::new()));
        }
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::compile(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_compile(&mut self) -> Compile {
        if self.has_compile() {
            match self.request.take() {
                ::std::option::Option::Some(ClientRequest_oneof_request::compile(v)) => v,
                _ => panic!(),
            }
        } else {
            Compile::new()
        }
    }

    pub fn get_compile<'a>(&'a self) -> &'a Compile {
        match self.request {
            ::std::option::Option::Some(ClientRequest_oneof_request::compile(ref v)) => v,
            _ => Compile::default_instance(),
        }
    }
}

impl ::protobuf::Message for ClientRequest {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.request = ::std::option::Option::Some(ClientRequest_oneof_request::get_stats(try!(is.read_message())));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.request = ::std::option::Option::Some(ClientRequest_oneof_request::shutdown(try!(is.read_message())));
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.request = ::std::option::Option::Some(ClientRequest_oneof_request::compile(try!(is.read_message())));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let ::std::option::Option::Some(ref v) = self.request {
            match v {
                &ClientRequest_oneof_request::get_stats(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ClientRequest_oneof_request::shutdown(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ClientRequest_oneof_request::compile(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
            };
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let ::std::option::Option::Some(ref v) = self.request {
            match v {
                &ClientRequest_oneof_request::get_stats(ref v) => {
                    try!(os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ClientRequest_oneof_request::shutdown(ref v) => {
                    try!(os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ClientRequest_oneof_request::compile(ref v) => {
                    try!(os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
            };
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<ClientRequest>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ClientRequest {
    fn new() -> ClientRequest {
        ClientRequest::new()
    }

    fn descriptor_static(_: ::std::option::Option<ClientRequest>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "get_stats",
                    ClientRequest::has_get_stats,
                    ClientRequest::get_get_stats,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "shutdown",
                    ClientRequest::has_shutdown,
                    ClientRequest::get_shutdown,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "compile",
                    ClientRequest::has_compile,
                    ClientRequest::get_compile,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ClientRequest>(
                    "ClientRequest",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ClientRequest {
    fn clear(&mut self) {
        self.clear_get_stats();
        self.clear_shutdown();
        self.clear_compile();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for ClientRequest {
    fn eq(&self, other: &ClientRequest) -> bool {
        self.request == other.request &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for ClientRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct CacheStatistic {
    // message fields
    name: ::protobuf::SingularField<::std::string::String>,
    // message oneof groups
    value: ::std::option::Option<CacheStatistic_oneof_value>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CacheStatistic {}

#[derive(Clone,PartialEq)]
pub enum CacheStatistic_oneof_value {
    count(u64),
    str(::std::string::String),
    size(u64),
}

impl CacheStatistic {
    pub fn new() -> CacheStatistic {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CacheStatistic {
        static mut instance: ::protobuf::lazy::Lazy<CacheStatistic> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CacheStatistic,
        };
        unsafe {
            instance.get(|| {
                CacheStatistic {
                    name: ::protobuf::SingularField::none(),
                    value: ::std::option::Option::None,
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // required string name = 1;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name<'a>(&'a mut self) -> &'a mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        };
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name<'a>(&'a self) -> &'a str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    // optional uint64 count = 2;

    pub fn clear_count(&mut self) {
        self.value = ::std::option::Option::None;
    }

    pub fn has_count(&self) -> bool {
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::count(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_count(&mut self, v: u64) {
        self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::count(v))
    }

    pub fn get_count<'a>(&self) -> u64 {
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::count(v)) => v,
            _ => 0,
        }
    }

    // optional string str = 3;

    pub fn clear_str(&mut self) {
        self.value = ::std::option::Option::None;
    }

    pub fn has_str(&self) -> bool {
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::str(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_str(&mut self, v: ::std::string::String) {
        self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::str(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_str<'a>(&'a mut self) -> &'a mut ::std::string::String {
        if let ::std::option::Option::Some(CacheStatistic_oneof_value::str(_)) = self.value {
        } else {
            self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::str(::std::string::String::new()));
        }
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::str(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_str(&mut self) -> ::std::string::String {
        if self.has_str() {
            match self.value.take() {
                ::std::option::Option::Some(CacheStatistic_oneof_value::str(v)) => v,
                _ => panic!(),
            }
        } else {
            ::std::string::String::new()
        }
    }

    pub fn get_str<'a>(&'a self) -> &'a str {
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::str(ref v)) => v,
            _ => "",
        }
    }

    // optional uint64 size = 4;

    pub fn clear_size(&mut self) {
        self.value = ::std::option::Option::None;
    }

    pub fn has_size(&self) -> bool {
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::size(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_size(&mut self, v: u64) {
        self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::size(v))
    }

    pub fn get_size<'a>(&self) -> u64 {
        match self.value {
            ::std::option::Option::Some(CacheStatistic_oneof_value::size(v)) => v,
            _ => 0,
        }
    }
}

impl ::protobuf::Message for CacheStatistic {
    fn is_initialized(&self) -> bool {
        if self.name.is_none() {
            return false;
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    try!(::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::count(try!(is.read_uint64())));
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::str(try!(is.read_string())));
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.value = ::std::option::Option::Some(CacheStatistic_oneof_value::size(try!(is.read_uint64())));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in self.name.iter() {
            my_size += ::protobuf::rt::string_size(1, &value);
        };
        if let ::std::option::Option::Some(ref v) = self.value {
            match v {
                &CacheStatistic_oneof_value::count(v) => {
                    my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
                },
                &CacheStatistic_oneof_value::str(ref v) => {
                    my_size += ::protobuf::rt::string_size(3, &v);
                },
                &CacheStatistic_oneof_value::size(v) => {
                    my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
                },
            };
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.name.as_ref() {
            try!(os.write_string(1, &v));
        };
        if let ::std::option::Option::Some(ref v) = self.value {
            match v {
                &CacheStatistic_oneof_value::count(v) => {
                    try!(os.write_uint64(2, v));
                },
                &CacheStatistic_oneof_value::str(ref v) => {
                    try!(os.write_string(3, v));
                },
                &CacheStatistic_oneof_value::size(v) => {
                    try!(os.write_uint64(4, v));
                },
            };
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<CacheStatistic>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CacheStatistic {
    fn new() -> CacheStatistic {
        CacheStatistic::new()
    }

    fn descriptor_static(_: ::std::option::Option<CacheStatistic>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_string_accessor(
                    "name",
                    CacheStatistic::has_name,
                    CacheStatistic::get_name,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_u64_accessor(
                    "count",
                    CacheStatistic::has_count,
                    CacheStatistic::get_count,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_string_accessor(
                    "str",
                    CacheStatistic::has_str,
                    CacheStatistic::get_str,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_u64_accessor(
                    "size",
                    CacheStatistic::has_size,
                    CacheStatistic::get_size,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CacheStatistic>(
                    "CacheStatistic",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CacheStatistic {
    fn clear(&mut self) {
        self.clear_name();
        self.clear_count();
        self.clear_str();
        self.clear_size();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for CacheStatistic {
    fn eq(&self, other: &CacheStatistic) -> bool {
        self.name == other.name &&
        self.value == other.value &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for CacheStatistic {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct CacheStats {
    // message fields
    stats: ::protobuf::RepeatedField<CacheStatistic>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CacheStats {}

impl CacheStats {
    pub fn new() -> CacheStats {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CacheStats {
        static mut instance: ::protobuf::lazy::Lazy<CacheStats> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CacheStats,
        };
        unsafe {
            instance.get(|| {
                CacheStats {
                    stats: ::protobuf::RepeatedField::new(),
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // repeated .sccache.CacheStatistic stats = 1;

    pub fn clear_stats(&mut self) {
        self.stats.clear();
    }

    // Param is passed by value, moved
    pub fn set_stats(&mut self, v: ::protobuf::RepeatedField<CacheStatistic>) {
        self.stats = v;
    }

    // Mutable pointer to the field.
    pub fn mut_stats<'a>(&'a mut self) -> &'a mut ::protobuf::RepeatedField<CacheStatistic> {
        &mut self.stats
    }

    // Take field
    pub fn take_stats(&mut self) -> ::protobuf::RepeatedField<CacheStatistic> {
        ::std::mem::replace(&mut self.stats, ::protobuf::RepeatedField::new())
    }

    pub fn get_stats<'a>(&'a self) -> &'a [CacheStatistic] {
        &self.stats
    }
}

impl ::protobuf::Message for CacheStats {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    try!(::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.stats));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in self.stats.iter() {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in self.stats.iter() {
            try!(os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited));
            try!(os.write_raw_varint32(v.get_cached_size()));
            try!(v.write_to_with_cached_sizes(os));
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<CacheStats>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CacheStats {
    fn new() -> CacheStats {
        CacheStats::new()
    }

    fn descriptor_static(_: ::std::option::Option<CacheStats>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_repeated_message_accessor(
                    "stats",
                    CacheStats::get_stats,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CacheStats>(
                    "CacheStats",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CacheStats {
    fn clear(&mut self) {
        self.clear_stats();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for CacheStats {
    fn eq(&self, other: &CacheStats) -> bool {
        self.stats == other.stats &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for CacheStats {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct ShuttingDown {
    // message fields
    stats: ::protobuf::SingularPtrField<CacheStats>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ShuttingDown {}

impl ShuttingDown {
    pub fn new() -> ShuttingDown {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ShuttingDown {
        static mut instance: ::protobuf::lazy::Lazy<ShuttingDown> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ShuttingDown,
        };
        unsafe {
            instance.get(|| {
                ShuttingDown {
                    stats: ::protobuf::SingularPtrField::none(),
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // required .sccache.CacheStats stats = 1;

    pub fn clear_stats(&mut self) {
        self.stats.clear();
    }

    pub fn has_stats(&self) -> bool {
        self.stats.is_some()
    }

    // Param is passed by value, moved
    pub fn set_stats(&mut self, v: CacheStats) {
        self.stats = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_stats<'a>(&'a mut self) -> &'a mut CacheStats {
        if self.stats.is_none() {
            self.stats.set_default();
        };
        self.stats.as_mut().unwrap()
    }

    // Take field
    pub fn take_stats(&mut self) -> CacheStats {
        self.stats.take().unwrap_or_else(|| CacheStats::new())
    }

    pub fn get_stats<'a>(&'a self) -> &'a CacheStats {
        self.stats.as_ref().unwrap_or_else(|| CacheStats::default_instance())
    }
}

impl ::protobuf::Message for ShuttingDown {
    fn is_initialized(&self) -> bool {
        if self.stats.is_none() {
            return false;
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    try!(::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.stats));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in self.stats.iter() {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.stats.as_ref() {
            try!(os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited));
            try!(os.write_raw_varint32(v.get_cached_size()));
            try!(v.write_to_with_cached_sizes(os));
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<ShuttingDown>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ShuttingDown {
    fn new() -> ShuttingDown {
        ShuttingDown::new()
    }

    fn descriptor_static(_: ::std::option::Option<ShuttingDown>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "stats",
                    ShuttingDown::has_stats,
                    ShuttingDown::get_stats,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ShuttingDown>(
                    "ShuttingDown",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ShuttingDown {
    fn clear(&mut self) {
        self.clear_stats();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for ShuttingDown {
    fn eq(&self, other: &ShuttingDown) -> bool {
        self.stats == other.stats &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for ShuttingDown {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct CompileStarted {
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CompileStarted {}

impl CompileStarted {
    pub fn new() -> CompileStarted {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CompileStarted {
        static mut instance: ::protobuf::lazy::Lazy<CompileStarted> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CompileStarted,
        };
        unsafe {
            instance.get(|| {
                CompileStarted {
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }
}

impl ::protobuf::Message for CompileStarted {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<CompileStarted>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CompileStarted {
    fn new() -> CompileStarted {
        CompileStarted::new()
    }

    fn descriptor_static(_: ::std::option::Option<CompileStarted>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let fields = ::std::vec::Vec::new();
                ::protobuf::reflect::MessageDescriptor::new::<CompileStarted>(
                    "CompileStarted",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CompileStarted {
    fn clear(&mut self) {
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for CompileStarted {
    fn eq(&self, other: &CompileStarted) -> bool {
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for CompileStarted {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct CompileFinished {
    // message fields
    stdout: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    stderr: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // message oneof groups
    exit_status: ::std::option::Option<CompileFinished_oneof_exit_status>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CompileFinished {}

#[derive(Clone,PartialEq)]
pub enum CompileFinished_oneof_exit_status {
    retcode(i32),
    signal(i32),
}

impl CompileFinished {
    pub fn new() -> CompileFinished {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CompileFinished {
        static mut instance: ::protobuf::lazy::Lazy<CompileFinished> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CompileFinished,
        };
        unsafe {
            instance.get(|| {
                CompileFinished {
                    stdout: ::protobuf::SingularField::none(),
                    stderr: ::protobuf::SingularField::none(),
                    exit_status: ::std::option::Option::None,
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // optional int32 retcode = 1;

    pub fn clear_retcode(&mut self) {
        self.exit_status = ::std::option::Option::None;
    }

    pub fn has_retcode(&self) -> bool {
        match self.exit_status {
            ::std::option::Option::Some(CompileFinished_oneof_exit_status::retcode(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_retcode(&mut self, v: i32) {
        self.exit_status = ::std::option::Option::Some(CompileFinished_oneof_exit_status::retcode(v))
    }

    pub fn get_retcode<'a>(&self) -> i32 {
        match self.exit_status {
            ::std::option::Option::Some(CompileFinished_oneof_exit_status::retcode(v)) => v,
            _ => 0,
        }
    }

    // optional int32 signal = 2;

    pub fn clear_signal(&mut self) {
        self.exit_status = ::std::option::Option::None;
    }

    pub fn has_signal(&self) -> bool {
        match self.exit_status {
            ::std::option::Option::Some(CompileFinished_oneof_exit_status::signal(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_signal(&mut self, v: i32) {
        self.exit_status = ::std::option::Option::Some(CompileFinished_oneof_exit_status::signal(v))
    }

    pub fn get_signal<'a>(&self) -> i32 {
        match self.exit_status {
            ::std::option::Option::Some(CompileFinished_oneof_exit_status::signal(v)) => v,
            _ => 0,
        }
    }

    // optional bytes stdout = 3;

    pub fn clear_stdout(&mut self) {
        self.stdout.clear();
    }

    pub fn has_stdout(&self) -> bool {
        self.stdout.is_some()
    }

    // Param is passed by value, moved
    pub fn set_stdout(&mut self, v: ::std::vec::Vec<u8>) {
        self.stdout = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_stdout<'a>(&'a mut self) -> &'a mut ::std::vec::Vec<u8> {
        if self.stdout.is_none() {
            self.stdout.set_default();
        };
        self.stdout.as_mut().unwrap()
    }

    // Take field
    pub fn take_stdout(&mut self) -> ::std::vec::Vec<u8> {
        self.stdout.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_stdout<'a>(&'a self) -> &'a [u8] {
        match self.stdout.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    // optional bytes stderr = 4;

    pub fn clear_stderr(&mut self) {
        self.stderr.clear();
    }

    pub fn has_stderr(&self) -> bool {
        self.stderr.is_some()
    }

    // Param is passed by value, moved
    pub fn set_stderr(&mut self, v: ::std::vec::Vec<u8>) {
        self.stderr = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_stderr<'a>(&'a mut self) -> &'a mut ::std::vec::Vec<u8> {
        if self.stderr.is_none() {
            self.stderr.set_default();
        };
        self.stderr.as_mut().unwrap()
    }

    // Take field
    pub fn take_stderr(&mut self) -> ::std::vec::Vec<u8> {
        self.stderr.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_stderr<'a>(&'a self) -> &'a [u8] {
        match self.stderr.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
}

impl ::protobuf::Message for CompileFinished {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.exit_status = ::std::option::Option::Some(CompileFinished_oneof_exit_status::retcode(try!(is.read_int32())));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.exit_status = ::std::option::Option::Some(CompileFinished_oneof_exit_status::signal(try!(is.read_int32())));
                },
                3 => {
                    try!(::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.stdout));
                },
                4 => {
                    try!(::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.stderr));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in self.stdout.iter() {
            my_size += ::protobuf::rt::bytes_size(3, &value);
        };
        for value in self.stderr.iter() {
            my_size += ::protobuf::rt::bytes_size(4, &value);
        };
        if let ::std::option::Option::Some(ref v) = self.exit_status {
            match v {
                &CompileFinished_oneof_exit_status::retcode(v) => {
                    my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
                },
                &CompileFinished_oneof_exit_status::signal(v) => {
                    my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
                },
            };
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.stdout.as_ref() {
            try!(os.write_bytes(3, &v));
        };
        if let Some(v) = self.stderr.as_ref() {
            try!(os.write_bytes(4, &v));
        };
        if let ::std::option::Option::Some(ref v) = self.exit_status {
            match v {
                &CompileFinished_oneof_exit_status::retcode(v) => {
                    try!(os.write_int32(1, v));
                },
                &CompileFinished_oneof_exit_status::signal(v) => {
                    try!(os.write_int32(2, v));
                },
            };
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<CompileFinished>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CompileFinished {
    fn new() -> CompileFinished {
        CompileFinished::new()
    }

    fn descriptor_static(_: ::std::option::Option<CompileFinished>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_i32_accessor(
                    "retcode",
                    CompileFinished::has_retcode,
                    CompileFinished::get_retcode,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_i32_accessor(
                    "signal",
                    CompileFinished::has_signal,
                    CompileFinished::get_signal,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor(
                    "stdout",
                    CompileFinished::has_stdout,
                    CompileFinished::get_stdout,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor(
                    "stderr",
                    CompileFinished::has_stderr,
                    CompileFinished::get_stderr,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CompileFinished>(
                    "CompileFinished",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CompileFinished {
    fn clear(&mut self) {
        self.clear_retcode();
        self.clear_signal();
        self.clear_stdout();
        self.clear_stderr();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for CompileFinished {
    fn eq(&self, other: &CompileFinished) -> bool {
        self.stdout == other.stdout &&
        self.stderr == other.stderr &&
        self.exit_status == other.exit_status &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for CompileFinished {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct UnhandledCompile {
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UnhandledCompile {}

impl UnhandledCompile {
    pub fn new() -> UnhandledCompile {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UnhandledCompile {
        static mut instance: ::protobuf::lazy::Lazy<UnhandledCompile> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UnhandledCompile,
        };
        unsafe {
            instance.get(|| {
                UnhandledCompile {
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }
}

impl ::protobuf::Message for UnhandledCompile {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<UnhandledCompile>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UnhandledCompile {
    fn new() -> UnhandledCompile {
        UnhandledCompile::new()
    }

    fn descriptor_static(_: ::std::option::Option<UnhandledCompile>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let fields = ::std::vec::Vec::new();
                ::protobuf::reflect::MessageDescriptor::new::<UnhandledCompile>(
                    "UnhandledCompile",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UnhandledCompile {
    fn clear(&mut self) {
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for UnhandledCompile {
    fn eq(&self, other: &UnhandledCompile) -> bool {
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for UnhandledCompile {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct UnknownCommand {
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UnknownCommand {}

impl UnknownCommand {
    pub fn new() -> UnknownCommand {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UnknownCommand {
        static mut instance: ::protobuf::lazy::Lazy<UnknownCommand> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UnknownCommand,
        };
        unsafe {
            instance.get(|| {
                UnknownCommand {
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }
}

impl ::protobuf::Message for UnknownCommand {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<UnknownCommand>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UnknownCommand {
    fn new() -> UnknownCommand {
        UnknownCommand::new()
    }

    fn descriptor_static(_: ::std::option::Option<UnknownCommand>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let fields = ::std::vec::Vec::new();
                ::protobuf::reflect::MessageDescriptor::new::<UnknownCommand>(
                    "UnknownCommand",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UnknownCommand {
    fn clear(&mut self) {
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for UnknownCommand {
    fn eq(&self, other: &UnknownCommand) -> bool {
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for UnknownCommand {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct ServerResponse {
    // message oneof groups
    response: ::std::option::Option<ServerResponse_oneof_response>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ServerResponse {}

#[derive(Clone,PartialEq)]
pub enum ServerResponse_oneof_response {
    stats(CacheStats),
    shutting_down(ShuttingDown),
    compile_started(CompileStarted),
    compile_finished(CompileFinished),
    unhandled_compile(UnhandledCompile),
    unknown(UnknownCommand),
}

impl ServerResponse {
    pub fn new() -> ServerResponse {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ServerResponse {
        static mut instance: ::protobuf::lazy::Lazy<ServerResponse> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ServerResponse,
        };
        unsafe {
            instance.get(|| {
                ServerResponse {
                    response: ::std::option::Option::None,
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // optional .sccache.CacheStats stats = 1;

    pub fn clear_stats(&mut self) {
        self.response = ::std::option::Option::None;
    }

    pub fn has_stats(&self) -> bool {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::stats(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_stats(&mut self, v: CacheStats) {
        self.response = ::std::option::Option::Some(ServerResponse_oneof_response::stats(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_stats<'a>(&'a mut self) -> &'a mut CacheStats {
        if let ::std::option::Option::Some(ServerResponse_oneof_response::stats(_)) = self.response {
        } else {
            self.response = ::std::option::Option::Some(ServerResponse_oneof_response::stats(CacheStats::new()));
        }
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::stats(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_stats(&mut self) -> CacheStats {
        if self.has_stats() {
            match self.response.take() {
                ::std::option::Option::Some(ServerResponse_oneof_response::stats(v)) => v,
                _ => panic!(),
            }
        } else {
            CacheStats::new()
        }
    }

    pub fn get_stats<'a>(&'a self) -> &'a CacheStats {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::stats(ref v)) => v,
            _ => CacheStats::default_instance(),
        }
    }

    // optional .sccache.ShuttingDown shutting_down = 2;

    pub fn clear_shutting_down(&mut self) {
        self.response = ::std::option::Option::None;
    }

    pub fn has_shutting_down(&self) -> bool {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_shutting_down(&mut self, v: ShuttingDown) {
        self.response = ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_shutting_down<'a>(&'a mut self) -> &'a mut ShuttingDown {
        if let ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(_)) = self.response {
        } else {
            self.response = ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(ShuttingDown::new()));
        }
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_shutting_down(&mut self) -> ShuttingDown {
        if self.has_shutting_down() {
            match self.response.take() {
                ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(v)) => v,
                _ => panic!(),
            }
        } else {
            ShuttingDown::new()
        }
    }

    pub fn get_shutting_down<'a>(&'a self) -> &'a ShuttingDown {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(ref v)) => v,
            _ => ShuttingDown::default_instance(),
        }
    }

    // optional .sccache.CompileStarted compile_started = 3;

    pub fn clear_compile_started(&mut self) {
        self.response = ::std::option::Option::None;
    }

    pub fn has_compile_started(&self) -> bool {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_compile_started(&mut self, v: CompileStarted) {
        self.response = ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_compile_started<'a>(&'a mut self) -> &'a mut CompileStarted {
        if let ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(_)) = self.response {
        } else {
            self.response = ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(CompileStarted::new()));
        }
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_compile_started(&mut self) -> CompileStarted {
        if self.has_compile_started() {
            match self.response.take() {
                ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(v)) => v,
                _ => panic!(),
            }
        } else {
            CompileStarted::new()
        }
    }

    pub fn get_compile_started<'a>(&'a self) -> &'a CompileStarted {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(ref v)) => v,
            _ => CompileStarted::default_instance(),
        }
    }

    // optional .sccache.CompileFinished compile_finished = 4;

    pub fn clear_compile_finished(&mut self) {
        self.response = ::std::option::Option::None;
    }

    pub fn has_compile_finished(&self) -> bool {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_compile_finished(&mut self, v: CompileFinished) {
        self.response = ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_compile_finished<'a>(&'a mut self) -> &'a mut CompileFinished {
        if let ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(_)) = self.response {
        } else {
            self.response = ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(CompileFinished::new()));
        }
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_compile_finished(&mut self) -> CompileFinished {
        if self.has_compile_finished() {
            match self.response.take() {
                ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(v)) => v,
                _ => panic!(),
            }
        } else {
            CompileFinished::new()
        }
    }

    pub fn get_compile_finished<'a>(&'a self) -> &'a CompileFinished {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(ref v)) => v,
            _ => CompileFinished::default_instance(),
        }
    }

    // optional .sccache.UnhandledCompile unhandled_compile = 5;

    pub fn clear_unhandled_compile(&mut self) {
        self.response = ::std::option::Option::None;
    }

    pub fn has_unhandled_compile(&self) -> bool {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_unhandled_compile(&mut self, v: UnhandledCompile) {
        self.response = ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_unhandled_compile<'a>(&'a mut self) -> &'a mut UnhandledCompile {
        if let ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(_)) = self.response {
        } else {
            self.response = ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(UnhandledCompile::new()));
        }
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_unhandled_compile(&mut self) -> UnhandledCompile {
        if self.has_unhandled_compile() {
            match self.response.take() {
                ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(v)) => v,
                _ => panic!(),
            }
        } else {
            UnhandledCompile::new()
        }
    }

    pub fn get_unhandled_compile<'a>(&'a self) -> &'a UnhandledCompile {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(ref v)) => v,
            _ => UnhandledCompile::default_instance(),
        }
    }

    // optional .sccache.UnknownCommand unknown = 6;

    pub fn clear_unknown(&mut self) {
        self.response = ::std::option::Option::None;
    }

    pub fn has_unknown(&self) -> bool {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::unknown(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_unknown(&mut self, v: UnknownCommand) {
        self.response = ::std::option::Option::Some(ServerResponse_oneof_response::unknown(v))
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_unknown<'a>(&'a mut self) -> &'a mut UnknownCommand {
        if let ::std::option::Option::Some(ServerResponse_oneof_response::unknown(_)) = self.response {
        } else {
            self.response = ::std::option::Option::Some(ServerResponse_oneof_response::unknown(UnknownCommand::new()));
        }
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::unknown(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_unknown(&mut self) -> UnknownCommand {
        if self.has_unknown() {
            match self.response.take() {
                ::std::option::Option::Some(ServerResponse_oneof_response::unknown(v)) => v,
                _ => panic!(),
            }
        } else {
            UnknownCommand::new()
        }
    }

    pub fn get_unknown<'a>(&'a self) -> &'a UnknownCommand {
        match self.response {
            ::std::option::Option::Some(ServerResponse_oneof_response::unknown(ref v)) => v,
            _ => UnknownCommand::default_instance(),
        }
    }
}

impl ::protobuf::Message for ServerResponse {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.response = ::std::option::Option::Some(ServerResponse_oneof_response::stats(try!(is.read_message())));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.response = ::std::option::Option::Some(ServerResponse_oneof_response::shutting_down(try!(is.read_message())));
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.response = ::std::option::Option::Some(ServerResponse_oneof_response::compile_started(try!(is.read_message())));
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.response = ::std::option::Option::Some(ServerResponse_oneof_response::compile_finished(try!(is.read_message())));
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.response = ::std::option::Option::Some(ServerResponse_oneof_response::unhandled_compile(try!(is.read_message())));
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.response = ::std::option::Option::Some(ServerResponse_oneof_response::unknown(try!(is.read_message())));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let ::std::option::Option::Some(ref v) = self.response {
            match v {
                &ServerResponse_oneof_response::stats(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ServerResponse_oneof_response::shutting_down(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ServerResponse_oneof_response::compile_started(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ServerResponse_oneof_response::compile_finished(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ServerResponse_oneof_response::unhandled_compile(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
                &ServerResponse_oneof_response::unknown(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
            };
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let ::std::option::Option::Some(ref v) = self.response {
            match v {
                &ServerResponse_oneof_response::stats(ref v) => {
                    try!(os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ServerResponse_oneof_response::shutting_down(ref v) => {
                    try!(os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ServerResponse_oneof_response::compile_started(ref v) => {
                    try!(os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ServerResponse_oneof_response::compile_finished(ref v) => {
                    try!(os.write_tag(4, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ServerResponse_oneof_response::unhandled_compile(ref v) => {
                    try!(os.write_tag(5, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
                &ServerResponse_oneof_response::unknown(ref v) => {
                    try!(os.write_tag(6, ::protobuf::wire_format::WireTypeLengthDelimited));
                    try!(os.write_raw_varint32(v.get_cached_size()));
                    try!(v.write_to_with_cached_sizes(os));
                },
            };
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields<'s>(&'s self) -> &'s ::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields<'s>(&'s mut self) -> &'s mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<ServerResponse>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ServerResponse {
    fn new() -> ServerResponse {
        ServerResponse::new()
    }

    fn descriptor_static(_: ::std::option::Option<ServerResponse>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "stats",
                    ServerResponse::has_stats,
                    ServerResponse::get_stats,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "shutting_down",
                    ServerResponse::has_shutting_down,
                    ServerResponse::get_shutting_down,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "compile_started",
                    ServerResponse::has_compile_started,
                    ServerResponse::get_compile_started,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "compile_finished",
                    ServerResponse::has_compile_finished,
                    ServerResponse::get_compile_finished,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "unhandled_compile",
                    ServerResponse::has_unhandled_compile,
                    ServerResponse::get_unhandled_compile,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor(
                    "unknown",
                    ServerResponse::has_unknown,
                    ServerResponse::get_unknown,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ServerResponse>(
                    "ServerResponse",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ServerResponse {
    fn clear(&mut self) {
        self.clear_stats();
        self.clear_shutting_down();
        self.clear_compile_started();
        self.clear_compile_finished();
        self.clear_unhandled_compile();
        self.clear_unknown();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for ServerResponse {
    fn eq(&self, other: &ServerResponse) -> bool {
        self.response == other.response &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for ServerResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

static file_descriptor_proto_data: &'static [u8] = &[
    0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
    0x12, 0x07, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x22, 0x0a, 0x0a, 0x08, 0x47, 0x65, 0x74,
    0x53, 0x74, 0x61, 0x74, 0x73, 0x22, 0x0a, 0x0a, 0x08, 0x53, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77,
    0x6e, 0x22, 0x27, 0x0a, 0x07, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x12, 0x0b, 0x0a, 0x03,
    0x63, 0x77, 0x64, 0x18, 0x01, 0x20, 0x02, 0x28, 0x09, 0x12, 0x0f, 0x0a, 0x07, 0x63, 0x6f, 0x6d,
    0x6d, 0x61, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x22, 0x8e, 0x01, 0x0a, 0x0d, 0x43,
    0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x26, 0x0a, 0x09,
    0x67, 0x65, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
    0x11, 0x2e, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61,
    0x74, 0x73, 0x48, 0x00, 0x12, 0x25, 0x0a, 0x08, 0x73, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e,
    0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65,
    0x2e, 0x53, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x48, 0x00, 0x12, 0x23, 0x0a, 0x07, 0x63,
    0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73,
    0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x48, 0x00,
    0x42, 0x09, 0x0a, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x57, 0x0a, 0x0e, 0x43,
    0x61, 0x63, 0x68, 0x65, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x12, 0x0c, 0x0a,
    0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x09, 0x12, 0x0f, 0x0a, 0x05, 0x63,
    0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x48, 0x00, 0x12, 0x0d, 0x0a, 0x03,
    0x73, 0x74, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x12, 0x0e, 0x0a, 0x04, 0x73,
    0x69, 0x7a, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x48, 0x00, 0x42, 0x07, 0x0a, 0x05, 0x76,
    0x61, 0x6c, 0x75, 0x65, 0x22, 0x34, 0x0a, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x53, 0x74, 0x61,
    0x74, 0x73, 0x12, 0x26, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
    0x0b, 0x32, 0x17, 0x2e, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43, 0x61, 0x63, 0x68,
    0x65, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x22, 0x32, 0x0a, 0x0c, 0x53, 0x68,
    0x75, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x44, 0x6f, 0x77, 0x6e, 0x12, 0x22, 0x0a, 0x05, 0x73, 0x74,
    0x61, 0x74, 0x73, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x73, 0x63, 0x63, 0x61,
    0x63, 0x68, 0x65, 0x2e, 0x43, 0x61, 0x63, 0x68, 0x65, 0x53, 0x74, 0x61, 0x74, 0x73, 0x22, 0x10,
    0x0a, 0x0e, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64,
    0x22, 0x65, 0x0a, 0x0f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x46, 0x69, 0x6e, 0x69, 0x73,
    0x68, 0x65, 0x64, 0x12, 0x11, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01,
    0x20, 0x01, 0x28, 0x05, 0x48, 0x00, 0x12, 0x10, 0x0a, 0x06, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c,
    0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x48, 0x00, 0x12, 0x0e, 0x0a, 0x06, 0x73, 0x74, 0x64, 0x6f,
    0x75, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x12, 0x0e, 0x0a, 0x06, 0x73, 0x74, 0x64, 0x65,
    0x72, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x0d, 0x0a, 0x0b, 0x65, 0x78, 0x69, 0x74,
    0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x12, 0x0a, 0x10, 0x55, 0x6e, 0x68, 0x61, 0x6e,
    0x64, 0x6c, 0x65, 0x64, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x22, 0x10, 0x0a, 0x0e, 0x55,
    0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x22, 0xc0, 0x02,
    0x0a, 0x0e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
    0x12, 0x24, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
    0x13, 0x2e, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43, 0x61, 0x63, 0x68, 0x65, 0x53,
    0x74, 0x61, 0x74, 0x73, 0x48, 0x00, 0x12, 0x2e, 0x0a, 0x0d, 0x73, 0x68, 0x75, 0x74, 0x74, 0x69,
    0x6e, 0x67, 0x5f, 0x64, 0x6f, 0x77, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e,
    0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x53, 0x68, 0x75, 0x74, 0x74, 0x69, 0x6e, 0x67,
    0x44, 0x6f, 0x77, 0x6e, 0x48, 0x00, 0x12, 0x32, 0x0a, 0x0f, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c,
    0x65, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
    0x17, 0x2e, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c,
    0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x48, 0x00, 0x12, 0x34, 0x0a, 0x10, 0x63, 0x6f,
    0x6d, 0x70, 0x69, 0x6c, 0x65, 0x5f, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x18, 0x04,
    0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x73, 0x63, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43,
    0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x48, 0x00,
    0x12, 0x36, 0x0a, 0x11, 0x75, 0x6e, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x64, 0x5f, 0x63, 0x6f,
    0x6d, 0x70, 0x69, 0x6c, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x73, 0x63,
    0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x55, 0x6e, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x64, 0x43,
    0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x48, 0x00, 0x12, 0x2a, 0x0a, 0x07, 0x75, 0x6e, 0x6b, 0x6e,
    0x6f, 0x77, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x63, 0x63, 0x61,
    0x63, 0x68, 0x65, 0x2e, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x43, 0x6f, 0x6d, 0x6d, 0x61,
    0x6e, 0x64, 0x48, 0x00, 0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
    0x4a, 0xa1, 0x12, 0x0a, 0x06, 0x12, 0x04, 0x0e, 0x00, 0x5e, 0x01, 0x0a, 0x08, 0x0a, 0x01, 0x02,
    0x12, 0x03, 0x0e, 0x08, 0x0f, 0x0a, 0x22, 0x0a, 0x02, 0x04, 0x00, 0x12, 0x03, 0x11, 0x00, 0x13,
    0x1a, 0x17, 0x20, 0x47, 0x65, 0x74, 0x20, 0x63, 0x61, 0x63, 0x68, 0x65, 0x20, 0x73, 0x74, 0x61,
    0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x00, 0x01,
    0x12, 0x03, 0x11, 0x08, 0x10, 0x0a, 0x22, 0x0a, 0x02, 0x04, 0x01, 0x12, 0x03, 0x14, 0x00, 0x13,
    0x1a, 0x17, 0x20, 0x53, 0x68, 0x75, 0x74, 0x20, 0x64, 0x6f, 0x77, 0x6e, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x01, 0x01,
    0x12, 0x03, 0x14, 0x08, 0x10, 0x0a, 0x24, 0x0a, 0x02, 0x04, 0x02, 0x12, 0x04, 0x17, 0x00, 0x1c,
    0x01, 0x1a, 0x18, 0x20, 0x52, 0x75, 0x6e, 0x20, 0x61, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c,
    0x65, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04,
    0x02, 0x01, 0x12, 0x03, 0x17, 0x08, 0x0f, 0x0a, 0x39, 0x0a, 0x04, 0x04, 0x02, 0x02, 0x00, 0x12,
    0x03, 0x19, 0x02, 0x1a, 0x1a, 0x2c, 0x20, 0x54, 0x68, 0x65, 0x20, 0x64, 0x69, 0x72, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x79, 0x20, 0x69, 0x6e, 0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x74, 0x6f,
    0x20, 0x72, 0x75, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
    0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x00, 0x04, 0x12, 0x03, 0x19, 0x02, 0x0a,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x00, 0x05, 0x12, 0x03, 0x19, 0x0b, 0x11, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x02, 0x02, 0x00, 0x01, 0x12, 0x03, 0x19, 0x12, 0x15, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x02, 0x02, 0x00, 0x03, 0x12, 0x03, 0x19, 0x18, 0x19, 0x0a, 0x25, 0x0a, 0x04, 0x04, 0x02,
    0x02, 0x01, 0x12, 0x03, 0x1b, 0x02, 0x1e, 0x1a, 0x18, 0x20, 0x54, 0x68, 0x65, 0x20, 0x66, 0x75,
    0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6e, 0x65, 0x2e,
    0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x01, 0x04, 0x12, 0x03, 0x1b, 0x02, 0x0a, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x01, 0x05, 0x12, 0x03, 0x1b, 0x0b, 0x11, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x02, 0x02, 0x01, 0x01, 0x12, 0x03, 0x1b, 0x12, 0x19, 0x0a, 0x0c, 0x0a, 0x05, 0x04,
    0x02, 0x02, 0x01, 0x03, 0x12, 0x03, 0x1b, 0x1c, 0x1d, 0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x03, 0x12,
    0x04, 0x1e, 0x00, 0x25, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x01, 0x12, 0x03, 0x1e, 0x08,
    0x15, 0x0a, 0x41, 0x0a, 0x04, 0x04, 0x03, 0x08, 0x00, 0x12, 0x04, 0x20, 0x02, 0x24, 0x03, 0x1a,
    0x33, 0x20, 0x41, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65,
    0x73, 0x74, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6f, 0x6e,
    0x65, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x69,
    0x6e, 0x67, 0x3a, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x08, 0x00, 0x01, 0x12, 0x03, 0x20,
    0x08, 0x0f, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x03, 0x02, 0x00, 0x12, 0x03, 0x21, 0x04, 0x1b, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x00, 0x06, 0x12, 0x03, 0x21, 0x04, 0x0c, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x03, 0x02, 0x00, 0x01, 0x12, 0x03, 0x21, 0x0d, 0x16, 0x0a, 0x0c, 0x0a, 0x05, 0x04,
    0x03, 0x02, 0x00, 0x03, 0x12, 0x03, 0x21, 0x19, 0x1a, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x03, 0x02,
    0x01, 0x12, 0x03, 0x22, 0x04, 0x1a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x06, 0x12,
    0x03, 0x22, 0x04, 0x0c, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x12, 0x03, 0x22,
    0x0d, 0x15, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x03, 0x12, 0x03, 0x22, 0x18, 0x19,
    0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x03, 0x02, 0x02, 0x12, 0x03, 0x23, 0x04, 0x18, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x03, 0x02, 0x02, 0x06, 0x12, 0x03, 0x23, 0x04, 0x0b, 0x0a, 0x0c, 0x0a, 0x05, 0x04,
    0x03, 0x02, 0x02, 0x01, 0x12, 0x03, 0x23, 0x0c, 0x13, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02,
    0x02, 0x03, 0x12, 0x03, 0x23, 0x16, 0x17, 0x0a, 0x27, 0x0a, 0x02, 0x04, 0x04, 0x12, 0x04, 0x28,
    0x00, 0x32, 0x01, 0x1a, 0x1b, 0x20, 0x41, 0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x63,
    0x61, 0x63, 0x68, 0x65, 0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x0a,
    0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x04, 0x01, 0x12, 0x03, 0x28, 0x08, 0x16, 0x0a, 0x0b, 0x0a, 0x04,
    0x04, 0x04, 0x02, 0x00, 0x12, 0x03, 0x29, 0x02, 0x1b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02,
    0x00, 0x04, 0x12, 0x03, 0x29, 0x02, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x00, 0x05,
    0x12, 0x03, 0x29, 0x0b, 0x11, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x00, 0x01, 0x12, 0x03,
    0x29, 0x12, 0x16, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x00, 0x03, 0x12, 0x03, 0x29, 0x19,
    0x1a, 0x0a, 0x0c, 0x0a, 0x04, 0x04, 0x04, 0x08, 0x00, 0x12, 0x04, 0x2a, 0x02, 0x31, 0x03, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x04, 0x08, 0x00, 0x01, 0x12, 0x03, 0x2a, 0x08, 0x0d, 0x0a, 0x20, 0x0a,
    0x04, 0x04, 0x04, 0x02, 0x01, 0x12, 0x03, 0x2c, 0x04, 0x15, 0x1a, 0x13, 0x20, 0x41, 0x20, 0x73,
    0x69, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x2e, 0x0a, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x01, 0x05, 0x12, 0x03, 0x2c, 0x04, 0x0a, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x04, 0x02, 0x01, 0x01, 0x12, 0x03, 0x2c, 0x0b, 0x10, 0x0a, 0x0c, 0x0a, 0x05, 0x04,
    0x04, 0x02, 0x01, 0x03, 0x12, 0x03, 0x2c, 0x13, 0x14, 0x0a, 0x1e, 0x0a, 0x04, 0x04, 0x04, 0x02,
    0x02, 0x12, 0x03, 0x2e, 0x04, 0x13, 0x1a, 0x11, 0x20, 0x41, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e,
    0x67, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02,
    0x02, 0x05, 0x12, 0x03, 0x2e, 0x04, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x02, 0x01,
    0x12, 0x03, 0x2e, 0x0b, 0x0e, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x02, 0x03, 0x12, 0x03,
    0x2e, 0x11, 0x12, 0x0a, 0x20, 0x0a, 0x04, 0x04, 0x04, 0x02, 0x03, 0x12, 0x03, 0x30, 0x04, 0x14,
    0x1a, 0x13, 0x20, 0x41, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x2c, 0x20, 0x69, 0x6e, 0x20, 0x62, 0x79,
    0x74, 0x65, 0x73, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x03, 0x05, 0x12, 0x03,
    0x30, 0x04, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x03, 0x01, 0x12, 0x03, 0x30, 0x0b,
    0x0f, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x04, 0x02, 0x03, 0x03, 0x12, 0x03, 0x30, 0x12, 0x13, 0x0a,
    0x29, 0x0a, 0x02, 0x04, 0x05, 0x12, 0x04, 0x35, 0x00, 0x37, 0x01, 0x1a, 0x1d, 0x20, 0x41, 0x20,
    0x6c, 0x69, 0x73, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x63, 0x61, 0x63, 0x68, 0x65, 0x20, 0x73, 0x74,
    0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x05,
    0x01, 0x12, 0x03, 0x35, 0x08, 0x12, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x05, 0x02, 0x00, 0x12, 0x03,
    0x36, 0x02, 0x24, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x05, 0x02, 0x00, 0x04, 0x12, 0x03, 0x36, 0x02,
    0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x05, 0x02, 0x00, 0x06, 0x12, 0x03, 0x36, 0x0b, 0x19, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x05, 0x02, 0x00, 0x01, 0x12, 0x03, 0x36, 0x1a, 0x1f, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x05, 0x02, 0x00, 0x03, 0x12, 0x03, 0x36, 0x22, 0x23, 0x0a, 0x2a, 0x0a, 0x02, 0x04,
    0x06, 0x12, 0x04, 0x3a, 0x00, 0x3c, 0x01, 0x1a, 0x1e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x73, 0x65,
    0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20, 0x73, 0x68, 0x75, 0x74, 0x74, 0x69, 0x6e, 0x67,
    0x20, 0x64, 0x6f, 0x77, 0x6e, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x06, 0x01, 0x12, 0x03,
    0x3a, 0x08, 0x14, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x06, 0x02, 0x00, 0x12, 0x03, 0x3b, 0x02, 0x20,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x06, 0x02, 0x00, 0x04, 0x12, 0x03, 0x3b, 0x02, 0x0a, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x06, 0x02, 0x00, 0x06, 0x12, 0x03, 0x3b, 0x0b, 0x15, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x06, 0x02, 0x00, 0x01, 0x12, 0x03, 0x3b, 0x16, 0x1b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x06,
    0x02, 0x00, 0x03, 0x12, 0x03, 0x3b, 0x1e, 0x1f, 0x0a, 0x38, 0x0a, 0x02, 0x04, 0x07, 0x12, 0x03,
    0x3f, 0x00, 0x19, 0x1a, 0x2d, 0x20, 0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x20, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x69,
    0x6e, 0x67, 0x20, 0x61, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x07, 0x01, 0x12, 0x03, 0x3f, 0x08, 0x16, 0x0a, 0x2f,
    0x0a, 0x02, 0x04, 0x08, 0x12, 0x04, 0x42, 0x00, 0x4c, 0x01, 0x1a, 0x23, 0x20, 0x54, 0x68, 0x65,
    0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x72, 0x61, 0x6e, 0x20, 0x61, 0x20, 0x63, 0x6f,
    0x6d, 0x70, 0x69, 0x6c, 0x65, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x2e, 0x0a, 0x0a,
    0x0a, 0x0a, 0x03, 0x04, 0x08, 0x01, 0x12, 0x03, 0x42, 0x08, 0x17, 0x0a, 0x2f, 0x0a, 0x04, 0x04,
    0x08, 0x08, 0x00, 0x12, 0x04, 0x44, 0x02, 0x49, 0x03, 0x1a, 0x21, 0x20, 0x54, 0x68, 0x65, 0x20,
    0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x08, 0x08, 0x00, 0x01, 0x12, 0x03, 0x44, 0x08, 0x13, 0x0a, 0x1b, 0x0a, 0x04, 0x04, 0x08,
    0x02, 0x00, 0x12, 0x03, 0x46, 0x04, 0x16, 0x1a, 0x0e, 0x20, 0x4e, 0x6f, 0x72, 0x6d, 0x61, 0x6c,
    0x20, 0x65, 0x78, 0x69, 0x74, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x00, 0x05,
    0x12, 0x03, 0x46, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x00, 0x01, 0x12, 0x03,
    0x46, 0x0a, 0x11, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x00, 0x03, 0x12, 0x03, 0x46, 0x14,
    0x15, 0x0a, 0x26, 0x0a, 0x04, 0x04, 0x08, 0x02, 0x01, 0x12, 0x03, 0x48, 0x04, 0x15, 0x1a, 0x19,
    0x20, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x61,
    0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x2e, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02,
    0x01, 0x05, 0x12, 0x03, 0x48, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x01, 0x01,
    0x12, 0x03, 0x48, 0x0a, 0x10, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x01, 0x03, 0x12, 0x03,
    0x48, 0x13, 0x14, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x08, 0x02, 0x02, 0x12, 0x03, 0x4a, 0x02, 0x1c,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x02, 0x04, 0x12, 0x03, 0x4a, 0x02, 0x0a, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x08, 0x02, 0x02, 0x05, 0x12, 0x03, 0x4a, 0x0b, 0x10, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x08, 0x02, 0x02, 0x01, 0x12, 0x03, 0x4a, 0x11, 0x17, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08,
    0x02, 0x02, 0x03, 0x12, 0x03, 0x4a, 0x1a, 0x1b, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x08, 0x02, 0x03,
    0x12, 0x03, 0x4b, 0x02, 0x1c, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x03, 0x04, 0x12, 0x03,
    0x4b, 0x02, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x03, 0x05, 0x12, 0x03, 0x4b, 0x0b,
    0x10, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x03, 0x01, 0x12, 0x03, 0x4b, 0x11, 0x17, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x08, 0x02, 0x03, 0x03, 0x12, 0x03, 0x4b, 0x1a, 0x1b, 0x0a, 0x43, 0x0a,
    0x02, 0x04, 0x09, 0x12, 0x03, 0x4f, 0x00, 0x1b, 0x1a, 0x38, 0x20, 0x54, 0x68, 0x65, 0x20, 0x73,
    0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20,
    0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x6d, 0x70,
    0x69, 0x6c, 0x65, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6e, 0x65,
    0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x09, 0x01, 0x12, 0x03, 0x4f, 0x08, 0x18, 0x0a, 0x34,
    0x0a, 0x02, 0x04, 0x0a, 0x12, 0x03, 0x52, 0x00, 0x19, 0x1a, 0x29, 0x20, 0x54, 0x68, 0x69, 0x73,
    0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x77, 0x61, 0x73, 0x20, 0x75, 0x6e, 0x6b,
    0x6e, 0x6f, 0x77, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x2e, 0x0a, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x0a, 0x01, 0x12, 0x03, 0x52, 0x08, 0x16,
    0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x0b, 0x12, 0x04, 0x54, 0x00, 0x5e, 0x01, 0x0a, 0x0a, 0x0a, 0x03,
    0x04, 0x0b, 0x01, 0x12, 0x03, 0x54, 0x08, 0x16, 0x0a, 0x42, 0x0a, 0x04, 0x04, 0x0b, 0x08, 0x00,
    0x12, 0x04, 0x56, 0x02, 0x5d, 0x03, 0x1a, 0x34, 0x20, 0x41, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65,
    0x72, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62,
    0x65, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x66, 0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x69, 0x6e, 0x67, 0x3a, 0x0a, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x0b, 0x08, 0x00, 0x01, 0x12, 0x03, 0x56, 0x08, 0x10, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x0b,
    0x02, 0x00, 0x12, 0x03, 0x57, 0x04, 0x19, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x00, 0x06,
    0x12, 0x03, 0x57, 0x04, 0x0e, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x00, 0x01, 0x12, 0x03,
    0x57, 0x0f, 0x14, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x00, 0x03, 0x12, 0x03, 0x57, 0x17,
    0x18, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x0b, 0x02, 0x01, 0x12, 0x03, 0x58, 0x04, 0x23, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x0b, 0x02, 0x01, 0x06, 0x12, 0x03, 0x58, 0x04, 0x10, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x0b, 0x02, 0x01, 0x01, 0x12, 0x03, 0x58, 0x11, 0x1e, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b,
    0x02, 0x01, 0x03, 0x12, 0x03, 0x58, 0x21, 0x22, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x0b, 0x02, 0x02,
    0x12, 0x03, 0x59, 0x04, 0x27, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x02, 0x06, 0x12, 0x03,
    0x59, 0x04, 0x12, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x02, 0x01, 0x12, 0x03, 0x59, 0x13,
    0x22, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x02, 0x03, 0x12, 0x03, 0x59, 0x25, 0x26, 0x0a,
    0x0b, 0x0a, 0x04, 0x04, 0x0b, 0x02, 0x03, 0x12, 0x03, 0x5a, 0x04, 0x29, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x0b, 0x02, 0x03, 0x06, 0x12, 0x03, 0x5a, 0x04, 0x13, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b,
    0x02, 0x03, 0x01, 0x12, 0x03, 0x5a, 0x14, 0x24, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x03,
    0x03, 0x12, 0x03, 0x5a, 0x27, 0x28, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x0b, 0x02, 0x04, 0x12, 0x03,
    0x5b, 0x04, 0x2b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x04, 0x06, 0x12, 0x03, 0x5b, 0x04,
    0x14, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x04, 0x01, 0x12, 0x03, 0x5b, 0x15, 0x26, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x04, 0x03, 0x12, 0x03, 0x5b, 0x29, 0x2a, 0x0a, 0x0b, 0x0a,
    0x04, 0x04, 0x0b, 0x02, 0x05, 0x12, 0x03, 0x5c, 0x04, 0x1f, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b,
    0x02, 0x05, 0x06, 0x12, 0x03, 0x5c, 0x04, 0x12, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x05,
    0x01, 0x12, 0x03, 0x5c, 0x13, 0x1a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x0b, 0x02, 0x05, 0x03, 0x12,
    0x03, 0x5c, 0x1d, 0x1e,
];

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
