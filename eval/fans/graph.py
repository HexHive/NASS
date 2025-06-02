import matplotlib.pyplot as plt
import matplotlib
import subprocess
import numpy as np
import json 
import os
import argparse
import sys
from matplotlib.ticker import MaxNLocator

BASE_DIR = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, "..", ".."))
sys.path.append(os.path.join(BASE_DIR, "..", "..", "fuzz"))

import triage 
import data.database as database
from config import FANS_EVAL_TIME, FUZZ_START_TIME, FUZZ_END_TIME, META_TARGET

binder_db = database.open_db()

if "CAMPAIGN_RUNTIME" in os.environ:
    CAMPAIGN_TIME = int(os.environ["CAMPAIGN_RUNTIME"])
else:
    CAMPAIGN_TIME = FANS_EVAL_TIME 

def parse_path(path):
    output_paths = []
    path_parts = path.split("/")
    idx_targets = path_parts.index("targets")
    idx_fuzzout = path_parts.index("fuzz_out")
    idx_service_name_1 = idx_targets+2
    idx_service_name_2 = idx_fuzzout-1
    if idx_service_name_1 == idx_service_name_2:
        service = path_parts[idx_service_name_1]
    else:
        service = ""
        for i in range(idx_service_name_1, idx_service_name_2+1):
            service += path_parts[i] + "/"
        service = service[:-1]
    device = path_parts[idx_targets+1]
    return device, service

def get_ordered_seeds(seed_dir):
    raw_list = []
    for f in os.listdir(seed_dir):
        seed_filename = f 
        seed_file = os.path.join(seed_dir, seed_filename)
        if os.path.isdir(seed_file):
            continue
        #print(seed_filename)
        seed_filename = seed_filename.split(".drcov")[0]
        iteration, sha1, timestamp = seed_filename.split("-")
        timestamp = int(timestamp)
        iteration = int(iteration)
        raw_list.append((iteration, timestamp, seed_file))
    ordered_data_seeds = [d[2] for d in sorted(raw_list, key=lambda x: (x[1], x[0]))]
    return ordered_data_seeds

def split_into_chunks(byte_array, chunk_size=8):
    # Ensure it's a list of byte chunks
    return [byte_array[i:i+chunk_size] for i in range(0, len(byte_array), chunk_size)]

def parse_bb(c):
    start = int.from_bytes(c[0:4], "little")
    size = int.from_bytes(c[4:6], "little")
    mod_id = int.from_bytes(c[6:8], "little")
    #print(hex(start), hex(size), mod_id)
    return start, size, mod_id

def get_bbs_unique(drcov_file):
    bb_data = open(drcov_file, 'rb').read()
    bb_blocks = bb_data[bb_data.find(b"bbs\n")+4:]
    id2path = {}
    bb_header = bb_data.split(b"\n")
    for line in bb_header:
        if b"Columns:" in line:
            continue
        if b"BB Table" in line:
            break
        #print(line)
        split = line.split(b",")
        if len(split) == 7:
            idd = int(split[0])
            path = split[-1]
            id2path[int(idd)] = path.decode()
    #print(id2path)
    #print(bb_blocks.hex())
    out_bbs = []
    # format is path_offsethex
    assert len(bb_blocks) % 8 == 0, "lenght of bb lbocks not correct"
    chunks = split_into_chunks(bb_blocks, 8)
    for c in chunks:
        start, size, mod_id = parse_bb(c)
        #print(f'fucked shit: {id2path[mod_id]}_{hex(start)}')
        out_bbs.append(f'{id2path[mod_id]}_{hex(start)}')
    out_bbs = list(set(out_bbs))
    return out_bbs 

def get_start_seed_time(path):
    ordered = get_ordered_seeds(path)
    first = ordered[0]
    return int(first.split(".drcov")[0].split("-")[-1])

def get_last_seed_time(path):
    ordered = get_ordered_seeds(path)
    last = ordered[-1]
    return int(last.split(".drcov")[0].split("-")[-1])

def get_seed_time(path):
    return int(path.split(".drcov")[0].split("-")[-1])

def get_fuzz_start_time(fuzz_dir):
    return int(open(os.path.join(fuzz_dir, FUZZ_START_TIME)).read())

def get_fuzz_end_time(fuzz_dir):
    try:
        return int(open(os.path.join(fuzz_dir, FUZZ_END_TIME)).read()) 
    except:
        print(f'{FUZZ_END_TIME} not found..')
        return None

def fix_seeds(drcov_seed_dir, fuzz_start_time):
    # happened that the emulator date was wrong, check if seeds have 
    # time < fuzz_start_time and adjust
    for f in get_ordered_seeds(drcov_seed_dir):
        seed_filename = os.path.basename(f).split(".drcov")[0]
        iteration, sha1, timestamp = seed_filename.split("-")
        timestamp = int(timestamp) 
        if timestamp < fuzz_start_time:
            new_seed_name = f'{iteration}-{sha1}-{fuzz_start_time}.drcov'
            new_seed_path = os.path.join(drcov_seed_dir, new_seed_name)
            print(f'[!] seed: {f} has messed up timestamp, chanign to {new_seed_path}')
            subprocess.check_output(f'mv {f} {new_seed_path}', shell=True)

def generate_coordinates(fuzz_dir):
    drcov_seed_dir = os.path.join(fuzz_dir, "drcov", "seeds")
    if not os.path.exists(drcov_seed_dir):
        print(f'seed drcov no exist: {drcov_seed_dir}')
        exit(-1)
    fuzz_start_time = get_fuzz_start_time(fuzz_dir)
    fix_seeds(drcov_seed_dir, fuzz_start_time)
    fuzz_end_time = get_fuzz_end_time(fuzz_dir)
    start_seed_time = get_start_seed_time(drcov_seed_dir)
    last_seed_time = get_last_seed_time(drcov_seed_dir)
    if fuzz_start_time is None:
        fuzz_start_time = start_seed_time
    if fuzz_end_time is None:
        fuzz_end_time = start_seed_time + CAMPAIGN_TIME
    t2bbs = {}
    for f in get_ordered_seeds(drcov_seed_dir):
        time = get_seed_time(f)
        bbs_retard = get_bbs_unique(f)
        if time in t2bbs:
            t2bbs[time] = list(set(t2bbs[time] + bbs_retard))
        else:
            t2bbs[time] = bbs_retard
    # sum up blocks
    t2bbcount = []
    bball = set()
    x = []
    y = []
    x.append(0)
    y.append(0)
    for t, bbs in t2bbs.items():
        t_normal = t - fuzz_start_time 
        for bb in bbs:
            bball.add(bb)
        x.append(t_normal)
        y.append(len(bball))
    # extend graph all the way
    x.append(CAMPAIGN_TIME)
    y.append(y[-1])
    #print(t2bbcount)
    #print(x)
    #print(y)
    return x,y

def plot_single(output_directory, service, dir_nass, dir_fans, 
                dir_nass_noprepoc, dir_nass_nodeser, fuzz_time):
    plt.clf()
    #plt.figure()
    if dir_nass is not None:
        # plot nass data
        x_nass, y_nass = generate_coordinates(dir_nass) 
        plt.plot(x_nass, y_nass, color='orange', label='nass')
    if dir_fans is not None:
        x_fans, y_fans = generate_coordinates(dir_fans) 
        plt.plot(x_fans, y_fans, color='green', label='fans')
    if dir_nass_noprepoc is not None:
        x_nass_nopreproc, y_nass_nopreproc = generate_coordinates(dir_nass_noprepoc)
        plt.plot(x_nass_nopreproc, y_nass_nopreproc, color='purple', label='nass_nopreproc')
    if dir_nass_nodeser is not None:
        x_nass_nodeser, y_nass_nodeser = generate_coordinates(dir_nass_nodeser)
        plt.plot(x_nass_nodeser, y_nass_nodeser, color='blue', label='nass_nodeser')


    plt.xlabel('time (s)')
    plt.ylabel('Basic Blocks')
    plt.title(service.replace("/", "_"))
    plt.legend()
    out_path = os.path.join(output_directory, f'{service.replace("/", "_")}_plot.pdf')
    plt.savefig(out_path, format="pdf")

def get_ys(coords, x):
    out = []
    for xc, yc in coords:
        if x in xc:
            out.append(yc[xc.index(x)])
        else:
            out.append(np.interp(x, xc, yc))
    return out

def aggregate(coords):
    y_max = []
    y_min = []
    y_med = []
    x_aggr = []
    all_x = set()
    for x, _ in coords:
        for xx in x:
            all_x.add(xx)
    x_aggr = list(sorted(list(all_x)))
    print(x_aggr)
    for x in x_aggr:
        all_y = get_ys(coords, x)
        y_max.append(max(all_y))
        y_min.append(min(all_y))
        y_med.append(np.median(all_y))
    return y_max, y_min, y_med, x_aggr

def get_100p_bbs(service, jsonp):
    jsonperc = json.load(open(jsonp))
    max_bbs = 0
    for s, d in jsonperc.items():
        if s == service:
            for f, dd in d.items():
                for ddd in dd:
                    if ddd["total"] > max_bbs:
                        max_bbs = ddd["total"]
    return max_bbs

def plot_multiple(output_directory, service, dirs_nass, dirs_fans, 
                dirs_fans_novarmap, dirs_nass_noprepoc, dirs_nass_nodeser, 
                dirs_nass_seeded, fuzz_time, jsonperc=None):
    plt.clf()
    matplotlib.rcParams['mathtext.fontset'] = 'custom'
    matplotlib.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
    matplotlib.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
    matplotlib.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
    matplotlib.rcParams['mathtext.fontset'] = 'stix'
    matplotlib.rcParams['font.family'] = 'STIXGeneral'
    #plt.figure()
    if dirs_nass is not None:
        nass_coords = []
        for dir_nass in dirs_nass:
            if dir_nass is None or not os.path.exists(os.path.join(dir_nass, "drcov", "seeds")):
                continue
            # plot nass data
            x_nass, y_nass = generate_coordinates(dir_nass) 
            nass_coords.append((x_nass, y_nass))
        y_nass_max, y_nass_min, y_nass_median, x_nass_aggr = aggregate(nass_coords)
        plt.fill_between(x_nass_aggr, y_nass_min, y_nass_max, color='orange', alpha=0.2)
        plt.plot(x_nass_aggr, y_nass_median, color='orange', label='nass')
        plt.plot(x_nass_aggr, y_nass_min, linestyle='none')
        plt.plot(x_nass_aggr, y_nass_max, linestyle='none')
    if dirs_fans is not None:
        fans_coords = []
        for dir_fans in dirs_fans:
            if dir_fans is None or not os.path.exists(os.path.join(dir_fans, "drcov", "seeds")):
                continue
            x_fans, y_fans = generate_coordinates(dir_fans) 
            fans_coords.append((x_fans, y_fans))
        y_fans_max, y_fans_min, y_fans_median, x_fans_aggr = aggregate(fans_coords)
        plt.fill_between(x_fans_aggr, y_fans_min, y_fans_max, color='green', alpha=0.2)
        plt.plot(x_fans_aggr, y_fans_median, color='green', label='fans', linestyle='dashed')
        plt.plot(x_fans_aggr, y_fans_min, linestyle='none')
        plt.plot(x_fans_aggr, y_fans_max, linestyle='none')
        print('fans max', max(y_fans_max))
    if dirs_fans_novarmap is not None:
        fans_novarmap_coords = []
        for dir_fans_novarmap in dirs_fans_novarmap:
            if dir_fans_novarmap is None or not os.path.exists(os.path.join(dir_fans_novarmap, "drcov", "seeds")):
                continue
            x_fans_novarmap, y_fans_novarmap = generate_coordinates(dir_fans_novarmap) 
            fans_novarmap_coords.append((x_fans_novarmap, y_fans_novarmap))
        y_fans_novarmap_max, y_fans_novarmap_min, y_fans_novarmap_median, x_fans_novarmap_aggr = aggregate(fans_novarmap_coords)
        plt.fill_between(x_fans_novarmap_aggr, y_fans_novarmap_min, y_fans_novarmap_max, color='brown', alpha=0.2)
        plt.plot(x_fans_novarmap_aggr, y_fans_novarmap_median, color='brown', label='fans_novarmap', linestyle='solid')
        plt.plot(x_fans_novarmap_aggr, y_fans_novarmap_min, linestyle='none')
        plt.plot(x_fans_novarmap_aggr, y_fans_novarmap_max, linestyle='none')
    if dirs_nass_noprepoc is not None:
        nass_nopreproc_coords = []
        for dir_nass_noprepoc in dirs_nass_noprepoc:
            if dir_nass_noprepoc is None or not os.path.exists(os.path.join(dir_nass_noprepoc, "drcov", "seeds")):
                continue
            x_nass_nopreproc, y_nass_nopreproc = generate_coordinates(dir_nass_noprepoc)
            nass_nopreproc_coords.append((x_nass_nopreproc, y_nass_nopreproc))
        y_npp_max, y_npp_min, y_npp_median, x_npp_aggr = aggregate(nass_nopreproc_coords)
        plt.fill_between(x_npp_aggr, y_npp_min, y_npp_max, color='purple', alpha=0.2)
        plt.plot(x_npp_aggr, y_npp_median, color='purple', label='nass_nopreproc', linestyle='dashdot')
        plt.plot(x_npp_aggr, y_npp_min, linestyle='none')
        plt.plot(x_npp_aggr, y_npp_max, linestyle='none')
    if dirs_nass_nodeser is not None:
        nass_no_deser = []
        for dir_nass_nodeser in dirs_nass_nodeser:
            if dir_nass_nodeser is None or not os.path.exists(os.path.join(dir_nass_nodeser, "drcov", "seeds")):
                continue
            x_nass_nodeser, y_nass_nodeser = generate_coordinates(dir_nass_nodeser)
            nass_no_deser.append((x_nass_nodeser, y_nass_nodeser))
        y_nd_max, y_nd_min, y_nd_median, x_nd_aggr = aggregate(nass_no_deser)
        plt.fill_between(x_nd_aggr, y_nd_min, y_nd_max, color='blue', alpha=0.2)
        plt.plot(x_nd_aggr, y_nd_median, color='blue', label='nass_nodeser', linestyle='dotted')
    if dirs_nass_seeded is not None:
        nass_seeded = []
        for dir_nass_seeded in dirs_nass_seeded:
            if dir_nass_seeded is None or not os.path.exists(os.path.join(dir_nass_seeded, "drcov", "seeds")):
                continue
            x_nass_seeded, y_nass_seeded = generate_coordinates(dir_nass_seeded)
            nass_seeded.append((x_nass_seeded, y_nass_seeded))
        y_sd_max, y_sd_min, y_sd_median, x_sd_aggr = aggregate(nass_seeded)
        plt.fill_between(x_sd_aggr, y_sd_min, y_sd_max, color='red', alpha=0.2)
        plt.plot(x_sd_aggr, y_sd_median, color='red', label='nass_seeded')


    #plt.xlabel('time (s)')
    #plt.ylabel('Basic Blocks')
    #plt.title(service)
    #plt.legend()
    
    
    plt.gca().set_xticklabels([])
    plt.gca().tick_params(axis='x', which='both', length=8)
    plt.gca().tick_params(axis='y', which='both', length=8)
    plt.gca().margins(y=0, x=0.005)
    ax = plt.gca()
    lines = ax.get_lines()
    max_y = max([max(line.get_ydata()) for line in lines])
    if jsonperc is None:
        # plot iwth percentage along the axis
        plt.ylim(0, max_y+max_y*0.05)
        #ax.set_yticks([0, int((max_y+max_y*0.05)/3), int(((max_y+max_y*0.05)*2)/3), int(max_y+max_y*0.05)])
        ax.yaxis.set_major_locator(MaxNLocator(nbins=5))
        ax.tick_params(axis='y', labelsize=20)
    else:
        onehbbs = get_100p_bbs(service, jsonperc) 
        plt.ylim(0, onehbbs) 
        yticks = [0, int(onehbbs/2), onehbbs]
        ylabels = ['','','']
        ax.set_yticks(yticks)
        ax.set_yticklabels([])
    if fuzz_time == 43200:
        xticks = [0, 18000, 36000]
        ax.set_xticks(xticks)
    elif fuzz_time == 86400:
        xticks = [0, 36000, 72000]
        ax.set_xticks(xticks)
    plt.tight_layout()
    #plt.gca().tick_params(axis='x', pad=10)
    #plt.gca().spines['bottom'].set_position(('data', 0))
    plt.gcf().subplots_adjust(left=0.115)
    out_path = os.path.join(output_directory, f'{service.replace("/", "_")}_plot.pdf')
    plt.savefig(out_path, format="pdf",bbox_inches='tight', pad_inches=0.1)


def plot_all(out_path, out_json, jsonperc=None):
    out_dir = os.path.join(os.path.dirname(out_path), 
                           os.path.basename(out_path).split(".json")[0])
    fuzz_time = out_json["time"]
    if os.path.exists(out_dir):
        os.system(f'rm -rf {out_dir}')
    os.system(f'mkdir {out_dir}')
    for s, s_entry in out_json["services"].items():
        print(f'plotting for {s}')
        if "nass" in s_entry:
            nass_out = s_entry["nass"]
            if nass_out is not None:
                if isinstance(nass_out, str):
                    drcov_seeds = os.path.join(nass_out, "drcov", "seeds")
                    if not os.path.exists(nass_out) or not os.path.exists(drcov_seeds):
                        print(f'NASS: {s} {drcov_seeds} does not exist...')
                        nass_out = None
            else:
                print(f'NASS: {s} entry is None..')
        else:
            nass_out = None
        if "fans" in s_entry:
            fans_out = s_entry["fans"]
            if fans_out is not None:
                if isinstance(fans_out, str):
                    drcov_seeds = os.path.join(fans_out, "drcov", "seeds")
                    if not os.path.exists(fans_out) or not os.path.exists(drcov_seeds):
                        print(f'FANS: {s} {drcov_seeds} does not exist...') 
                        fans_out = None
            else: 
                print(f'FANS: {s} entry is None..')
        else:
            fans_out = None
        if "fans_novarmap" in s_entry:
            fans_novarmap_out = s_entry["fans_novarmap"]
            if fans_novarmap_out is not None:
                if isinstance(fans_novarmap_out, str):
                    drcov_seeds = os.path.join(fans_novarmap_out, "drcov", "seeds")
                    if not os.path.exists(fans_novarmap_out) or not os.path.exists(drcov_seeds):
                        print(f'FANS NOVARMAP: {s} {drcov_seeds} does not exist...') 
                        fans_novarmap_out = None
            else: 
                print(f'FANS NOVARMAP: {s} entry is None..')
        else:
            fans_novarmap_out = None
        if "nass_nopreproc" in s_entry:
            nass_nopreproc_out = s_entry["nass_nopreproc"]
            if nass_nopreproc_out is not None:
                if isinstance(nass_nopreproc_out, str):
                    drcov_seeds = os.path.join(nass_nopreproc_out, "drcov", "seeds")
                    if not os.path.exists(nass_nopreproc_out) or not os.path.exists(drcov_seeds):
                        print(f'NASS nopreproc: {s} {drcov_seeds} does not exist...') 
                        nass_nopreproc_out = None 
            else:
                print(f'NASS nopreproc: {s} entry is None..')
        else:
            nass_nopreproc_out = None
        if "nass_nodeser" in s_entry:
            nass_nodeser_out = s_entry["nass_nodeser"]
            if nass_nodeser_out is not None:
                if isinstance(nass_nodeser_out, str):
                    drcov_seeds = os.path.join(nass_nodeser_out, "drcov", "seeds")
                    if not os.path.exists(nass_nodeser_out) or not os.path.exists(drcov_seeds):
                        print(f'NASS nopreproc: {s} {drcov_seeds} does not exist...') 
                        nass_nodeser_out = None 
            else:
                print(f'NASS nopreproc: {s} entry is None..')
        else:
            nass_nodeser_out = None 
        if "nass_seeded" in s_entry:
            nass_seeded = s_entry["nass_seeded"]
            if nass_seeded is not None:
                if isinstance(nass_seeded, str):
                    drcov_seeds = os.path.join(nass_seeded, "drcov", "seeds")
                    if not os.path.exists(nass_seeded) or not os.path.exists(drcov_seeds):
                        print(f'NASS nopreproc: {s} {drcov_seeds} does not exist...') 
                        nass_seeded = None 
            else:
                print(f'NASS nopreproc: {s} entry is None..')
        else:
            nass_seeded = None 
        plot_multiple(out_dir, s, nass_out, fans_out, fans_novarmap_out, nass_nopreproc_out, nass_nodeser_out, nass_seeded, fuzz_time, jsonperc=jsonperc) 
        #plot_single(out_dir, s, nass_out, fans_out, nass_nopreproc_out, nass_nodeser_out, fuzz_time) 

def is_frida(backtrace):
    for m in backtrace:
        if "frida" in m[1]:
            return True
    return False


def get_out_info(s, o):
    svc_entry = database.get_service(binder_db, s, META_TARGET)
    if svc_entry is not None:
        service_binary = svc_entry.binary_path
    else:
        service_binary = None
    if o is None:
        return None, None
    if isinstance(o, str):
        if not os.path.exists(o) or not os.path.exists(os.path.join(o, "data")):
            return None, None
        crashes = []
        log_dir = os.path.join(o, "logs")
        crashes_unique = triage.get_crashes(log_dir, service_binary)
        seeds = [
            f for f in os.listdir(os.path.join(o, "data")) 
            if not f.endswith(".rng")
        ] 
        #if len(crashes_unique) > 10:
            #breakpoint()
        #print(crashes_unique)
        return len(seeds), crashes_unique
    else:
        log_tmp = os.path.join("tmp", "logtmp")
        os.system(f'rm -rf {log_tmp} && mkdir -p {log_tmp}')
        seedss = []
        for o_p in o:
            if o_p is None or not os.path.exists(o_p) or not os.path.exists(os.path.join(o_p, "data")):
                continue
            log_dir = os.path.join(o_p, "logs")
            os.system(f'cp {log_dir}/* {log_tmp}/')
            seeds = [
                f for f in os.listdir(os.path.join(o_p, "data")) 
                if not f.endswith(".rng")
            ]             
            seedss.append(len(seeds))
        crashes_unique = triage.get_crashes(log_tmp, service_binary)
        return int(sum(seedss)/len(seedss)), len(crashes_unique)


def print_info(out_json):
    print(f'INFO: fuzzed for {out_json["time"]} seconds')
    for s, s_entry in out_json["services"].items():
        print(f'-----{s}------')
        if "nass" not in s_entry:
            print(f'NASS {s} no entry..')
        else:
            nass_out = s_entry["nass"]
            seeds, crashes = get_out_info(s, nass_out)
            print(f'NASS: {s} {seeds} seeds, {crashes} crashes')
        if "nass_nopreproc" in s_entry:
            nass_out = s_entry["nass_nopreproc"]
            seeds, crashes = get_out_info(s, nass_out)
            print(f'NASS NO PREPROC: {s} {seeds} seeds, {crashes} crashes')
        if "nass_nodeser" in s_entry:
            nass_out = s_entry["nass_nodeser"]
            seeds, crashes = get_out_info(s, nass_out)
            print(f'NASS NO DESER: {s} {seeds} seeds, {crashes} crashes')
        if "fans" not in s_entry:
            print(f'FANS {s} no entry..')
        else:
            fans_out = s_entry["fans"]
            seeds, crashes = get_out_info(s, fans_out)
            print(f'FANS: {s} {seeds} seeds, {crashes} crashes')
        if "fans_novarmap" in s_entry:
            fans_out = s_entry["fans_novarmap"]
            seeds, crashes = get_out_info(s, fans_out)
            print(f'FANS NOVARMAP: {s} {seeds} seeds, {crashes} crashes')


if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(
        description=f"Replay seeds against a service to refine seeds or extract \
        drcov coverage"
    )
    parser.add_argument(
        "-j",
        "--json_out",
        type=str,
        required=True,
        help="path to output of fans-run.py",
    )
    parser.add_argument(
        "--no_graph",
        action="store_true",
        help="dont graph",
    )
    parser.add_argument(
        "--jsonperc",
        type=str,
        required=False,
        help="path to json percentage file",
    )
    args = parser.parse_args()

    out_json = json.load(open(args.json_out))

    print_info(out_json)
    if not args.no_graph:
        plot_all(args.json_out, out_json, jsonperc=args.jsonperc)
