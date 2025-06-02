import utils

maps = open("tmp/maps").read()
out = utils.parse_proc_maps(maps)

print(out)
