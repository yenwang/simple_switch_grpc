import nnpy

sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
sub.connect('ipc:///tmp/bmv2-0-notifications.ipc')
sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
msg = sub.recv()
print msg
