require 'json'

items = JSON.load(IO.read("./syscalls_32.json"))['aaData']

open "syscall_32.md", "w:UTF-8" do |io|
  items.each do |id, name, args, eax, ebx, ecx, edx, esi, edi, defintaion|
    io << "#{id} | #{name} | #{args} | #{eax} | #{ebx['type']} | #{ecx['type']} | #{edx['type']} | #{esi['type']} | #{edi['type']} | #{defintaion}\n"
  end
end