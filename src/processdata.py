from collections import namedtuple
import pandas as pd
from datetime import datetime
from itertools import accumulate
from numpy import diff
import pprint
from mitre_vars import mitre_techniques
import seaborn as sns
import string
import random
from collections import defaultdict
import re, json
import os, shutil
import math
import sys
import logging

SPDFA = True
anon_mapping = dict()

Alert = namedtuple('Alert', ['host', 'sign', 'attackStage', 'sev', 'ts', 'diff'])
EpisodeNW = namedtuple('EpisodeNW', ['ts', 'sign', 'attackStage', 'sev', 'stateID'])
AGNode = namedtuple('AGNode', ['label', 'ts', 'sign', 'sev'])

logger = logging.getLogger('mylogger')
logger.setLevel(logging.DEBUG)

def anon_data(filename):
    df = pd.read_csv(filename)
    new_rows = []
    anon_hosts = []
    cnt = 0
    relevant_df = df[['TimeGenerated', 'AlertName', 'Severity', 'Tactics', 'Techniques', 'TechKey', 'AttackStage', 'Indicator']].copy()

    for _, row in df.iterrows():
        type = row['IndicatorType']
        if type != 'HostName' and type != 'IPAddress':
            continue
        host = row['Indicator']
        if host in anon_mapping:
            host = anon_mapping[host]
        else:
            anon_str = 'HOST' + str(cnt)
            cnt += 1
            anon_mapping[host] = anon_str
            host = anon_str
        new_rows.append(row)
        anon_hosts.append(host)
        
    new_df = pd.DataFrame(new_rows, columns=relevant_df.columns)
    new_df['AnonHost'] = anon_hosts
    new_df.reset_index(inplace=True)
    new_df.to_csv(filename + '_anon.csv')  


def load_data(filename):
    df = pd.read_csv(filename)
    prev = -1
    data: list[Alert] = []

    for _, row in df.iterrows():
        host = row['AnonHost']
        ts = row['TimeGenerated']

        # limit microseconds to 6 digits
        micros = ts.split('.')[1].split('+')[0][:6]
        new_ts = ts.rsplit(".", 1)[0] + '.' + micros + '+' + ts.split("+", 1)[1]
    
        dt = datetime.strptime(new_ts, '%Y-%m-%d %H:%M:%S.%f%z')# 2018-11-03 23:16:09.148520+00:00
        DIFF = 0.0 if prev == -1 else round((dt - prev).total_seconds(),2)
        prev = dt

        sig = row['AlertName']
        cat = str(row['AttackStage'])
        sev = row['Severity']
        data.append(Alert(host, sig, cat, sev, dt, DIFF))

    data = sorted(data, key=lambda x: x.ts)
    return data

def removeDup(unparse, duplicate_as=False, t=1.0):
    if duplicate_as:
        li = [unparse[x] for x in range(1,len(unparse)) if not (unparse[x].diff <= t  # Diff from previous alert is less than x sec
                                                                and unparse[x].host == unparse[x-1].host # same host
                                                                and unparse[x].sign == unparse[x-1].sign # same alert type
                                                                and unparse[x].attackStage == unparse[x-1].attackStage
                                                            )]
    else:
        li = [unparse[x] for x in range(1,len(unparse)) if not (unparse[x].diff <= t  # Diff from previous alert is less than x sec
                                                        and unparse[x].host == unparse[x-1].host # same host
                                                        and unparse[x].sign == unparse[x-1].sign # same alert type
                                                    )]
    return li

def get_eps(data: list[Alert]):
    host_data: dict[str, list[EpisodeNW]] = dict()
    # group alerts by host and make each alert into an episode
    for alert in data:
        host = alert.host
        ep = EpisodeNW(alert.ts, alert.sign, alert.attackStage, alert.sev, None)
        if host in host_data.keys():
            host_data[host].append(ep)
        else:
            host_data[host] = [ep]

    for host in host_data:
        host_data[host].sort(key=lambda tup: tup[0])
    return host_data

def break_into_subbehaviors(host_data: dict[str, list[EpisodeNW]]):
    keys: list[str] = []
    alerts: list[EpisodeNW] = []
    cutlen = 4

    for victim, episodes in host_data.items():
        if len(episodes) < 2:
            continue
        pieces = math.floor(len(episodes)/cutlen)
        if pieces < 1:
            keys.append(victim)
            alerts.append(episodes)
        else:
            c = 0
            # get sev
            sevs = [x.sev for x in episodes]
            # cut when episode sequence go from higher severity to a lower one
            cuts = [i for i in range(len(episodes) - 1) if (sevs[i] == 'Medium' and sevs[i + 1] == 'Low') or (sevs[i] == 'High' and sevs[i + 1] == 'Low') or (sevs[i] == 'High' and sevs[i + 1] == 'Medium')]
            if len(cuts) == 0:
                keys.append(victim)
                alerts.append(episodes)
            else:
                rest = (-1,-1)
                for i in range(len(cuts)):
                    start, end = 0, 0
                    if i == 0:
                        start = 0
                        end = cuts[i]
                    else:
                        start = cuts[i-1]+1
                        end = cuts[i]
                    rest = (end + 1, len(sevs)-1)
                    al = episodes[start:end+1]
                    if len(al) < 2:
                        continue
                    keys.append(victim)
                    alerts.append(al)
                    c += 1
                al = episodes[rest[0]: rest[1]+1]
                if len(al) < 2:
                    continue
                keys.append(victim)
                alerts.append(al)
    logger.debug('# sub-sequences ' + str(len(keys)))
    return (alerts, keys)

def generate_traces(alerts, datafile):
    count_lines = 0
    count_cats = set()
    traces = []

    f = open(datafile, 'w')
    lines = []
    for episodes in alerts:
        if len(episodes) < 2:
            continue
        count_lines += 1
        # symbol is attack stage | severity
        trace = [x.attackStage.replace(' ', '').replace(',', '-') + '|' + x.sev for x in episodes]
        for symb in trace:
            count_cats.add(symb)
        
        if SPDFA == True:
            trace.reverse()
        st = '1' + " "+ str(len(trace)) + ' ' + ' '.join(trace) + '\n'
        lines.append(st)
        traces.append(trace)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()
    logger.debug('unqiue symbols ' + str(count_cats))
    return traces


def loadmodel(modelfile):

  """Wrapper to load resulting model json file

   Keyword arguments:
   modelfile -- path to the json model file
  """

  # because users can provide unescaped new lines breaking json conventions
  # in the labels, we are removing them from the label fields
  with open(modelfile) as fh:
    data = fh.read()
  data = re.sub( r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', data )

  data = data.replace('\n', '').replace(',,', ',')#.replace(', ,', ',')#.replace('\t', ' ')


  data = re.sub(',+', ',', data)
  machine = json.loads(data)


  dfa = defaultdict(lambda: defaultdict(str))

  for edge in machine["edges"]:
      dfa[ edge["source"] ][ edge["name"] ] = (edge["target"], edge["appearances"])

  for entry in machine["nodes"]:
      dfa[ str(entry['id']) ]["type"] = "0"
      dfa[str(entry['id']) ]["isred"] = int(entry['isred'])

  return (dfa, machine)


def traverse(dfa, sinks, sequence, statelist=False):
    """Wrapper to traverse a given model with a string

    Keyword arguments:
    dfa -- loaded model
    sequence -- space-separated string to accept/reject in dfa
    """
    #in_main_model = set()
    sev_sinks = set()
    state = "0"
    stlst = ["0"]
    for event in sequence:
        sym = event.split(":")[0]
        state = dfa[state][sym]

        if state == "":
            # return -1 for low sev symbols
            sev = sym.split('|')[1]
            if sev == 'Medium' or sev == 'High':
                try:
                    state = sinks[stlst[-1]][sym][0]
                    sev_sinks.add(state)
                except:
                    state = '-1'
            else:
                state = '-1'
        else:
            try:
                state = state[0]
            except IndexError:
                logger.error("Out of alphabet: alternatives")

                stlst.append("-1")
                if not statelist:
                    return dfa[state]["type"] == "1"
                else:
                    return (dfa[state]["type"] == "1", stlst)
        stlst.append(state)
    if not statelist:
        return dfa[state]["type"] == "1"
    else:
        return (dfa[state]["type"] == "1", stlst, sev_sinks)
    

def encode_sequences(traces, m, m2):
    num_sink = 0
    total = 0
    state_traces = dict()
    med_states = set()
    sev_states = set()
    sev_sinks = set()

    for i,sample in enumerate(traces):
        _, s, sevsinks = traverse(m, m2, sample, statelist=True)
        state_traces[i] = [(x) for x in s]

        total += len(s)
        true = [1 if x == '-1' else 0 for x in s]

        num_sink += sum(true)

        assert (len(sample) + 1 == len(state_traces[i]))

        # find severe states
        sev_sinks.update(sevsinks)
        s = s[1:]
        med = [int(state) for sym, state in zip(sample, s) if sym.split('|')[1] == 'Medium' ]
        med_states.update(med)
        sev = [int(state) for sym, state in zip(sample, s) if sym.split('|')[1] == 'High' ]
        sev_states.update(sev)
    
    med_states = med_states.difference(sev_states)
    logger.debug('Traces in sinks: ' + str(num_sink) + ' Total traces: ' + str(total) + ' Percentage: ' + str(100*(num_sink/float(total))))
    logger.debug('Total medium states ' + str(len(med_states)))
    logger.debug('Total severe states ' + str(len(sev_states)))
    return (state_traces, med_states, sev_states, sev_sinks)


# recombine alerts by host
def make_condensed_data(alerts : list[list[EpisodeNW]], keys: str, state_traces: list[list[str]]):
    condensed_data: dict[str, list[EpisodeNW]]= dict()

    cnt = 0
    for victim, episodes in zip(keys, alerts):
        if len(episodes) < 2:
            continue

        # reverse traces again to match original epsiode order
        new_state = (state_traces[cnt][1:])[::-1]

        # also artifically add tiny delay so all events are not exactly at the same time.
        # start time, endtime, episode mas, state ID, most frequent service, list of unique signatures, (1st and last timestamp)
        new_ep = [EpisodeNW(ep.ts, ep.sign, ep.attackStage, ep.sev, new_state[i]) for i, ep in enumerate(episodes)]

        # dictionary with attack-victim key, value list of all sub attempts for the key, ordered by start time
        if victim not in condensed_data:
            condensed_data[victim] = []
        condensed_data[victim].extend(new_ep)
        cnt += 1
    
    for k in condensed_data:
        condensed_data[k].sort(key=lambda tup: tup.ts)  # sorts in place based on starting times
    return condensed_data

def translate(label, root=False):
    new_label = ""
    parts = label.split("|")
    if root:
        new_label += 'Victim: '+str(root)+'\n'

    if len(parts) >= 1:
        new_label += parts[0]
        if ',' in new_label:
            techs = parts[0].split(',')
            new_label = ('\n').join(techs)
    # if len(parts) >= 2:
    #     new_label += "\n" + parts[1]
    # if len(parts) >= 3:
    #     new_label += '' if parts[2] == '' else '\n' + 'ID: ' + parts[2]
    if len(parts) >= 2:
        new_label += '' if parts[1] == '' else '\n' + 'ID: ' + parts[1]

    return new_label


def make_AG(condensed_data: dict[str, list[EpisodeNW]], sev_sinks: set[str], dirname, victim_host):
    global w
    dirname += '/AGs'
    try:
        if os.path.exists(dirname):
            shutil.rmtree(dirname)
        os.mkdir(dirname)
    except:
        logger.error("Can't create directory here")
    else:
        logger.debug("Successfully created directory for AGs")

    # all IDs in the main model (including high-sev sinks)
    in_main_model = [[episode.stateID for episode in sequence] for sequence in condensed_data.values()]
    in_main_model = set([item for sublist in in_main_model for item in sublist])

    # all high episodes for every host
    attacks = set()
    if victim_host != None:
        for episode in condensed_data[victim_host]:
            if episode.sev == 'High':
                vert_name = episode.attackStage
                attacks.add((victim_host, vert_name))
    else:
        for host in condensed_data.keys():
            for episode in condensed_data[host]:
                if episode.sev == 'High':
                    vert_name = episode.attackStage
                    attacks.add((host, vert_name))
    attacks = list(attacks)
    #attacks = ['Credential Access.OS Credential Dumping']
    #attacks = ['Defense Evasion']
    for (v_host, attack) in attacks:
        logger.debug('GENERATING AG FOR ' +  v_host + ' ' + attack)
        ep_sequence = []
        attempts: list[list[AGNode]] = []
        attack_vnames = set()
        for ep in condensed_data[v_host]:
            timestamp = ep.ts
            cat = ep.attackStage
            sign = ep.sign
            sev = ep.sev
            stateID = -1
            if ep.stateID in in_main_model:
                stateID = '' if ep.sev == 'Low' else str(ep.stateID)
            else:
                stateID = '|Sink'

            #vert_name = cat + '|' + ep.ts[0].strftime("%d/%m/%y, %H:%M:%S") + '|' + stateID 
            vert_name = cat + '|' + stateID 
            
            ep_sequence.append(AGNode(vert_name, timestamp, sign, sev))
            # add to attempts and continue processing further
            if cat == attack and sev == 'High':
                attempts.append(ep_sequence)
                last_action = ep_sequence[-1]
                ep_sequence = [last_action]
                attack_vnames.add(vert_name)
        logger.debug('observed objectives' +  str(attack_vnames))
        logger.debug('FOUND ' + str(len(attempts)) + ' attempts')

        AGname = attack.replace('|', '').replace('_','').replace('-','').replace('(','').replace(')', '').replace(' ', '').replace('.', '').replace(',', '')
        lines = []
        lines.append((0,'digraph '+ AGname + ' {'))
        lines.append((0,'rankdir="BT"; \n graph [ nodesep="0.1", ranksep="0.02"] \n node [ fontname=Arial, fontsize=24,penwidth=3]; \n edge [ fontname=Arial, fontsize=20,penwidth=5 ];'))
        root_node = translate(attack, root=v_host)
        lines.append((0, '"'+root_node+'" [shape=doubleoctagon, style=filled, fillcolor=salmon];'))
        lines.append((0, '{ rank = max; "'+root_node+'"}'))

        for obj in list(attack_vnames):
            lines.append((0,'"'+translate(obj)+'" -> "'+root_node+'"'))
            sinkflag = False
            for sink in sev_sinks:
                if obj.endswith(sink):
                    sinkflag = True
                    break
            if sinkflag:
                lines.append((0,'"'+translate(obj)+'" [style="dotted, filled", fillcolor= salmon]'))
            else:
                lines.append((0,'"'+translate(obj)+'" [style=filled, fillcolor= salmon]'))

        samerank = '{ rank=same; "'+ '" "'.join([translate(x) for x in attack_vnames]) # all obj variants have the same rank
        samerank += '"}'
        lines.append((0,samerank))
        
        already_addressed = set()
        nodes = {}
        node_sev = {}
        attackerID = 'HACKER'

        for attempt in attempts: # iterate over each attempt
            # record all nodes
            for action in attempt:
                if action.label not in nodes.keys():
                    nodes[action.label] = set()
                nodes[action.label].add(action.sign)
                node_sev[action.label] = action.sev
            # nodes
            for vid, (vname, ts, sign, sev) in enumerate(attempt): # iterate over each action in an attempt
                if vid == 0: # if first action
                    cl = ', fillcolor= yellow' if sev != 'High' else ''
                    if 'Sink' in vname: # if sink, make dotted
                        lines.append((0,'"'+translate(vname)+'" [style="dotted,filled"' + cl + ']'))
                    else:
                        sinkflag = False
                        for sink in sev_sinks:
                            if vname.endswith(sink): # else if a high-sev sink, make dotted too
                                sinkflag = True
                                break
                        if sinkflag:
                            lines.append((0,'"'+translate(vname)+'" [style="dotted,filled"' + cl + ']'))
                            already_addressed.add(vname.split('|')[1])
                        else: # else, normal starting node
                            lines.append((0,'"'+translate(vname)+'" [style=filled' + cl + ']'))
                else: # for other actions
                    if 'Sink' in vname: # if sink
                        line = [x[1] for x in lines] # take all AG graph lines so far, and see if it was ever defined before, re-define it to be dotted
                        quit = False
                        for l in line:
                            if (translate(vname) in l) and ('dotted' in l) and ('->' not in l): # if already defined as dotted, move on
                                quit = True
                                break
                        if quit:
                            continue
                        partial = '"'+translate(vname) + '" [style="dotted' # redefine here
                        if not sum([True if partial in x else False for x in line]):
                            lines.append((0,partial+'"]'))

            # transitions
            fontcolor = 'dimgray'
            color = 'tomato'
            bi = zip(attempt, attempt[1:]) # make bigrams (sliding window of 2)
            for vid,((vname1, ts1, _, _),(vname2, ts2, _, _)) in enumerate(bi): # for every bigram
                _from_last = ts1.strftime("%d/%m/%y, %H:%M:%S")
                _to_first = ts2.strftime("%d/%m/%y, %H:%M:%S")
                gap = round((ts2 - ts1).total_seconds())
                gap_str = ''
                if gap > 3600:
                    gap_str = "{:.1f}".format(gap/3600) + ' h'
                elif gap > 60:
                    gap_str = "{:.1f}".format(gap/60) + ' min'
                else:
                    gap_str = str(gap) + ' sec'
                if vid == 0:
                    lines.append((ts1, '"' + translate(vname1) + '"' + ' -> ' + '"' + translate(vname2) +
                                    '"' + ' [ label="' + 
                                    'prev_ts: ' + _from_last + '\n' +
                                    'next_ts: ' + _to_first + '\n' +
                                    'gap: ' + gap_str + '\n' + 
                                    'action no. ' + str(vid + 1) + 
                                    '"]' +
                                    '[ fontcolor="' + fontcolor + '" color=' + color + ']'
                                    ))
                else:
                    lines.append((ts1, '"' + translate(vname1) + '"' + ' -> ' + '"' + translate(vname2) +
                                    '"' + ' [ label="' + 
                                    #'end_prev: ' + _from_last + '\n' +
                                    #'start_next: ' + _to_first + '\n' +
                                    '  ts: ' + _to_first + '\n' +
                                    'gap: ' + gap_str + '\n' + 
                                    'action no. ' + str(vid + 1) + 
                                    '"]' +
                                    '[ fontcolor="' + fontcolor + '" color=' + color + ']'
                                    ))

        for vname, signatures in nodes.items(): # Go over all vertices again and define their shapes + make high-sev sink states dotted
            shape = 'oval'
            if node_sev[vname] == 'Medium':
                shape = 'box'
            elif node_sev[vname] == 'High':
                shape = 'hexagon'
            if shape == 'oval' or vname.split('|')[1] in already_addressed: # if it's oval, we dont do anything because its not high-sev sink
                lines.append((0,'"'+translate(vname)+'" [shape='+shape+']'))
            else:
                sinkflag = False
                for sink in sev_sinks:
                    if vname.endswith(sink):
                        sinkflag = True
                        break
                if sinkflag:
                    if node_sev[vname] == 'High' and attack in vname:
                        lines.append((0,'"'+translate(vname)+'" [style="dotted,filled", fillcolor= salmon, shape='+shape+']'))
                    else: 
                        lines.append((0,'"'+translate(vname)+'" [style="dotted", shape='+shape+']'))
                else:
                    lines.append((0,'"'+translate(vname)+'" [shape='+shape+']'))
            # add tooltip
            lines.append((1, '"'+translate(vname)+'"'+' [tooltip="'+ "\n".join(signatures) +'"]'))
        lines.append((1000,'}'))

        out_f_name = dirname + '/' + v_host + AGname
        f = open(out_f_name + '.dot', 'w')
        for l in lines:
            f.write(l[1])
            f.write('\n')
        f.close()

        os.system("dot -Tpng " + out_f_name + ".dot -o " + out_f_name + ".png")
        #os.system("dot -Tsvg "+ out_f_name + ".dot -o " + out_f_name + ".svg")
        os.system('rm ' + out_f_name + '.dot')


def setup_logging(logfile):
    fh = logging.FileHandler(logfile, 'w')
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

def main():
    gen_trace_only = False
    # whether to keep duplicates if two alerts have same time but different attack stage
    dup_as = False
    filename = ''
    dirname = ''
    if len(sys.argv) < 4:
        print('expected at least 3 arguments, got less')
        exit(-1)
    # alert csv file location
    filename = sys.argv[1]
    # tracefile name
    traceFile = sys.argv[2]
    # where to gen output and the rest of AGS
    dirname = sys.argv[3]
    # whether to generate traces and quit afterwards
    if (len(sys.argv) == 5):
        gen_trace_only = True if sys.argv[4] == '--traces-only' else False

    setup_logging('exec.log')

    data = load_data(filename)
    logger.debug('BEFORE DUP REMOVAL ' + str(len(data)) +  ' alerts')

    data_nodup = removeDup(data, dup_as)
    logger.debug('AFTER DUP REMOVAL ' + str(len(data_nodup)) + ' alerts')

    host_eps = get_eps(data_nodup)
    logger.debug('got ' + str(sum([len(x) for x in host_eps.values()])) + ' episodes')

    alerts, keys  = break_into_subbehaviors(host_eps)
    logger.debug('got ' + str(len(keys)) + ' SUBSEQUENCES')

    traces = generate_traces(alerts, traceFile)
    if gen_trace_only:
        exit()

    os.system('sh start.sh ag-test .')
    os.system('cp -fR output/* ' + dirname)

    m, data = loadmodel(traceFile + ".ff.final.json")
    m2, _ = loadmodel(traceFile + ".ff.finalsinks.json")

    (state_traces, _, _, sev_sinks) = encode_sequences(traces, m, m2)

    condensed_data = make_condensed_data(alerts, keys, state_traces)

    cnt = 0
    logger.debug('FINAL CONDENSED DATA')
    for k, v in condensed_data.items():
        logger.debug('VICTIM ' + k)
        for i, ep in enumerate(v):
            logger.debug('EPISODE' + str(i))
            logger.debug(str(ep))
            cnt += 1
        logger.debug('')
    logger.debug(str(cnt))

    make_AG(condensed_data, sev_sinks, dirname, None)

if __name__ == "__main__":
    main()

