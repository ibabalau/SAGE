from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt
import pandas as pd
import subprocess
import re
from time import sleep
import os
import shutil
import logging

from sage_package.sage_func import load_data, aggregate_into_episodes, host_episode_sequences, break_into_subbehaviors, \
                                    generate_traces, loadmodel, encode_sequences, find_severe_states, make_condensed_data, \
                                    traverse, make_av_data, make_AG, translate, small_mapping, micro, rev_smallmapping
from sage_package.prediction import pdfa_predict_next_action, parse_file

def plot_alert_num_time(alerts, interval):
    event_times = [ev[8] for ev in alerts]

    event_times = pd.to_datetime(event_times) 
    s = pd.Series(range(len(event_times)), index=event_times)  # create a Series
    s_resampled = s.resample(interval).count()  # resample by day and count the number of events

    plt.figure(figsize=(12,6))
    plt.plot(s_resampled.index, s_resampled)
    plt.title('Number of events over time')
    plt.xlabel('Time')
    plt.ylabel('Number of events')
    #plt.show()
    # Save the plot to a file
    plt.savefig('/Users/ionbabalau/uni/thesis/SAGE/plots/team7alerts' + interval + '.png', dpi=300)

def most_frequent(serv): 
    max_frequency = 0
    most_frequent_service = None
    for s in serv:
       frequency = serv.count(s)
       if frequency > max_frequency:
            most_frequent_service = s
            max_frequency = frequency
    return most_frequent_service

def ess_to_trace(ess):
    episodes = ess
    mcats = [str(x[2]) for x in episodes]
    max_servs = [most_frequent(x[6]) for x in episodes]

    multi = [str(small_mapping[int(c)]) + "|" + str(s) for (c,s) in zip(mcats, max_servs)]
    return multi

def write_traces_to_file(traces, datafile):
    count_lines = 0
    count_cats = set()

    f = open(datafile, 'w')
    lines = []
    for trace in traces:
        if len(trace) < 3:
            continue
        count_lines += 1
        rev_trace = trace.copy()
        rev_trace.reverse()
        for e in rev_trace:
            feat = e.split(':')[0]
            count_cats.add(feat)
        st = '1' + " "+ str(len(trace)) + ' ' + ' '.join(rev_trace) + '\n'
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()

def encode_sequences_traces(m, m2, traces):
    num_sink = 0
    total = 0
    state_traces = dict()
    samples = [' '.join(i) for i in traces]
    for i, sample in enumerate(samples):
        r, s, _ = traverse(m, m2, sample, statelist=True)
        s = [(x) for x in s]
        state_traces[i] = s
        total += len(s)
        true = [1 if x == '-1' else 0 for x in s]
        num_sink += sum(true)
        print('encoded', sample, state_traces[i])
        assert (len(sample.split(' '))+1 == len(state_traces[i]))

    print('Traces in sinks: ', num_sink, 'Total traces: ', total, 'Percentage: ',100*(num_sink / float(total)))
    return (samples, state_traces)

def run_flexfringe(*args, **kwargs):
    """Wrapper to call the flexfringe binary

    Keyword arguments:
    position 0 -- input file with trace samples
    kwargs -- list of key=value arguments to pass as command line arguments
    """
    command = ['--help']

    if(len(kwargs) >= 1):
        command = []
        for key in kwargs:
            command += ['--' + key + '=' + kwargs[key]]

    result = subprocess.run([flexfringe_path + '/flexfringe',] + command + [args[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    print(result.returncode, result.stdout, result.stderr)


    try:
        with open('dfafinal.dot') as fh:
            return fh.read()
    except FileNotFoundError:
        pass

    return 'No output file was generated.'

def fix_syntax(fname):
    with open(fname, 'r') as file:
        filedata = file.read()
    stripped = re.sub('[\s+]', '', filedata)
    extracommas = re.search('(}(,+)\]}$)', stripped)
    if extracommas is not None:
        c = (extracommas.group(0)).count(',')
        print(extracommas.group(0), c)
        filedata = ''.join(filedata.rsplit(',', c))
        with open(fname, 'w') as file:
            file.write(filedata)

def update_condensed_data(alerts, keys, state_traces, med_states, sev_states, condensed_data):
    counter = -1
    freq_distrib = {}
    for tid, (attacker, episodes) in enumerate(zip(keys, alerts)):
        if len(episodes) < 3:
            continue
        #print(' ------------- COUNTER ', counter, '------')
        counter += 1

        if '10.0.254' not in attacker:
            continue
        if ('147.75' in attacker or '69.172'  in attacker):
                continue
        
        max_servs = [most_frequent(x[6]) for x in episodes]
        new_state = (state_traces[counter][1:])[::-1]

        times = [(x[0], x[1], x[2], int(new_state[i]), max_servs[i], x[7], x[8]) for i,x in enumerate(episodes)] # start time, endtime, episode mas, state ID, most frequent service, list of unique signatures, (1st and last timestamp)
        step1 = attacker.split('->')
        step1_0 = step1[0].split('-')[0]
        step1_1 = step1[0].split('-')[1]
        step2 = step1[-1].split('-')[0]
        real_attacker = '->'.join([step1_0+'-'+step1_1, step2])
        real_attacker_inv = '->'.join([step1_0+'-'+step2, step1_1])
        #print(real_attacker)
        # t0-10.0.254.103->10.0.0.11
        INV = False
        key = real_attacker
        if '10.0.254' in step2:
            INV = True
            key = real_attacker_inv

        if real_attacker not in condensed_data.keys() and real_attacker_inv not in condensed_data.keys():
            condensed_data[key] = []

        # dictionary with attack-victim key, value list of all sub attempts for the key, ordered by start time
        for ep in times:
            condensed_data[real_attacker_inv].extend(times)
            

    for k in condensed_data:
        condensed_data[k].sort(key=lambda tup: tup[0])  # sorts in place based on starting times
    #print('High-severity objective states', levelone, len(levelone))
    return condensed_data


def make_AG_RT(condensed_v_data, condensed_data, state_groups, sev_sinks, datafile, expname, batch_no):
    global w
    SAVE = 1
    tcols = {
        't0': 'maroon',
        't1': 'orange',
        't2': 'darkgreen',
        't3': 'blue',
        't4': 'magenta',
        't5': 'purple',
        't6': 'brown',
        't7': 'tomato',
        't8': 'turquoise',
        't9': 'skyblue',
    }
    if SAVE:
        try:
            dirname = expname + 'AGs/' + str(batch_no)
            if os.path.isdir('dirname'):
                shutil.rmtree(dirname)
            os.mkdir(dirname)
        except:
            print("Can't create directory here")
        else:
            print("Successfully created directory for AGs")

    shapes = ['oval', 'oval', 'oval', 'box', 'box', 'box', 'box', 'hexagon', 'hexagon', 'hexagon', 'hexagon', 'hexagon']
    in_main_model = [[episode[3] for episode in sequence] for sequence in condensed_data.values()] # all IDs in the main model (including high-sev sinks)
    in_main_model = set([item for sublist in in_main_model for item in sublist])

    ser_total = dict()
    simple = dict()
    total_victims = set([x.split('-')[1] for x in list(condensed_v_data.keys())]) # collect all victim IPs

    # true if we want only MAS, false if we want mas+service
    OBJ_ONLY = False # Experiment 1: mas+service or only mas?
    attacks = set()
    for episodes in condensed_data.values(): # iterate over all episodes and collect the objective nodes.
        for ep in episodes: # iterate over every episode
            # only high severity will have triple digit mcat
            if len(str(ep[2])) == 3: # If high-seveity, then include it
                cat = micro[ep[2]].split('.')[1]
                vert_name = None
                if OBJ_ONLY:
                    vert_name = cat
                else:
                    vert_name = cat+'|'+ep[4] # cat + service
                attacks.add(vert_name)
    # list of objectives
    attacks = list(attacks)

    for int_victim in total_victims:  # iterate over every victim
        print('\n!!! Rendering AGs for Victim ', int_victim,'\n',  sep=' ', end=' ', flush=True)
        for attack in attacks: # iterate over every attack
            print('\t!!!! Objective ', attack,'\n',  sep=' ', end=' ', flush=True)
            collect = dict()
            
            # dictionary with key: attacker, value list of episodes for the current objective
            team_level = dict()
            # will contain current objective that was found in an episode list
            observed_obj = set() # variants of current objective
            nodes = {}
            vertices, edges = 0, 0
            for att, episodes in condensed_data.items(): # iterate over (a,v): [episode, episode, episode]
                if int_victim not in att: # if it's not the right victim, then don't process further
                    continue
                vname_time = []
                for ep in episodes:
                    start_time = round(ep[0]/1.0)
                    end_time = round(ep[1]/1.0)
                    cat = micro[ep[2]].split('.')[1]
                    signs = ep[5]
                    timestamps = ep[6]
                    stateID = -1
                    if ep[3] in in_main_model:
                        stateID = '' if len(str(ep[2])) == 1 else '|'+str(ep[3])
                    else:
                        stateID = '|Sink'

                    vert_name = cat + '|'+ ep[4] + stateID
                    
                    vname_time.append((vert_name, start_time, end_time, signs, timestamps))
                    
                if not sum([True if attack in x[0] else False for x in vname_time]): # if the objective is never reached, don't process further
                    continue

                # if it's an episode sequence targetting the requested victim and obtaining the requested objective,
                attempts = []
                sub_attempt = []
                for (vname, start_time, end_time, signs, ts) in vname_time: # cut each attempt until the requested objective
                    sub_attempt.append((vname, start_time, end_time, signs, ts)) # add the vertex in path
                    if attack in vname: # if it's the objective
                        if len(sub_attempt) <= 1: ## If only a single node, reject
                            sub_attempt = []
                            continue
                        attempts.append(sub_attempt)
                        sub_attempt = []
                        observed_obj.add(vname)
                        continue
                team_attacker = att.split('->')[0] # team+attacker
                if team_attacker not in team_level.keys():
                    team_level[team_attacker] = []

                team_level[team_attacker].extend(attempts)
                #team_level[team_attacker] = sorted(team_level[team_attacker], key=lambda item: item[1])
            #print(observed_obj)
            # print('elements in graph', team_level.keys(), sum([len(x) for x in team_level.values()]))

            for k, v in team_level.items():
                print(k)
                for attempts in v:
                    for attempt in attempts:
                        print(attempt)
                    print('attempt finished')
                print()

            if sum([len(x) for x in team_level.values()]) == 0: # if no team obtains this objective or targets this victim, don't generate its AG.
                print('SKIPPING THIS')
                continue
            
            AGname = attack.replace('|', '').replace('_','').replace('-','').replace('(','').replace(')', '')
            lines = []
            lines.append((0,'digraph '+ AGname + ' {'))
            lines.append((0,'rankdir="BT"; \n graph [ nodesep="0.1", ranksep="0.02"] \n node [ fontname=Arial, fontsize=24,penwidth=3]; \n edge [ fontname=Arial, fontsize=20,penwidth=5 ];'))
            root_node = translate(attack, root=int_victim)
            lines.append((0, '"'+root_node+'" [shape=doubleoctagon, style=filled, fillcolor=salmon];'))
            lines.append((0, '{ rank = max; "'+root_node+'"}'))

            for obj in list(observed_obj): # for each variant of objective, add a link to the root node, and determine if it's sink
                lines.append((0,'"'+translate(obj)+'" -> "'+root_node+'"'))

                sinkflag = False
                for sink in sev_sinks:
                    if obj.endswith(sink):
                        sinkflag = True
                        break
                if sinkflag:
                    lines.append((0,'"'+translate(obj)+'" [style="filled,dotted", fillcolor= salmon]'))
                else:
                    lines.append((0,'"'+translate(obj)+'" [style=filled, fillcolor= salmon]'))

            samerank = '{ rank=same; "'+ '" "'.join([translate(x) for x in observed_obj]) # all obj variants have the same rank
            samerank += '"}'
            lines.append((0,samerank))

            already_addressed = set()
            for attackerID,attempts in team_level.items(): # for every attacker that obtains this objective
                color = tcols[attackerID.split('-')[0]] # team color
                ones = [''.join([action[0] for action in attempt]) for attempt in attempts]
                unique = len(set(ones)) # count exactly unique attempts
                #print(unique)
                #print('team', attackerID, 'total paths', len(attempts), 'unique paths', unique, 'longest path:', max([len(x) for x in attempts]), \
                #     'shortest path:', min([len(x) for x in attempts]))

                #path_info[attack][attackerID].append((len(attempts), unique, max([len(x) for x in attempts]), min([len(x) for x in attempts])))
                for attempt in attempts: # iterate over each attempt
                    # record all nodes
                    for action in attempt:
                        if action[0] not in nodes.keys():
                            nodes[action[0]] = set()
                        nodes[action[0]].update(action[3])
                    # nodes will contain a set of signatures
                    print('NODES')
                    print(attackerID)
                    print(attempt)
                    print(nodes)
                    for vid,(vname,start_time,end_time,signs,_) in enumerate(attempt): # iterate over each action in an attempt
                        if vid == 0: # if first action
                            if 'Sink' in vname: # if sink, make dotted
                                lines.append((0,'"'+translate(vname)+'" [style="dotted,filled", fillcolor= yellow]'))
                            else:
                                sinkflag = False
                                for sink in sev_sinks:
                                    if vname.endswith(sink): # else if a high-sev sink, make dotted too
                                        sinkflag = True
                                        break
                                if sinkflag:
                                    lines.append((0,'"'+translate(vname)+'" [style="dotted,filled", fillcolor= yellow]'))
                                    already_addressed.add(vname.split('|')[2])
                                else: # else, normal starting node
                                    lines.append((0,'"'+translate(vname)+'" [style=filled, fillcolor= yellow]'))
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
                                partial = '"'+translate(vname)+'" [style="dotted' # redefine here
                                if not sum([True if partial in x else False for x in line]):
                                    lines.append((0,partial+'"]'))

                    # transitions
                    bi = zip(attempt, attempt[1:]) # make bigrams (sliding window of 2)
                    for vid,((vname1,time1,etime1, signs1, ts1),(vname2,_,_, signs2, ts2)) in enumerate(bi): # for every bigram
                        _from_last = ts1[1].strftime("%d/%m/%y, %H:%M:%S")
                        _to_first = ts2[0].strftime("%d/%m/%y, %H:%M:%S")
                        gap = round((ts2[0] - ts1[1]).total_seconds())
                        if vid == 0:  # first transition, add attacker IP
                            lines.append((time1, '"' + translate(vname1) + '"' + ' -> ' + '"' + translate(vname2) +
                                          '" [ color=' + color + '] ' + '[label=<<font color="' + color + '"> start_next: ' + _to_first + '<br/>gap: ' +
                                          str(gap) + 'sec<br/>end_prev: ' + _from_last + '</font><br/><font color="' + color + '"><b>Attacker: ' +
                                          attackerID.split('-')[1] + '</b></font>>]'
                                          ))
                        else:
                            lines.append((time1, '"' + translate(vname1) + '"' + ' -> ' + '"' + translate(vname2) +
                                          '"' + ' [ label="start_next: ' + _to_first + '\ngap: ' +
                                          str(gap) + 'sec\nend_prev: ' + _from_last + '"]' + '[ fontcolor="' + color + '" color=' + color + ']'
                                          ))

            for vname, signatures in nodes.items(): # Go over all vertices again and define their shapes + make high-sev sink states dotted
                mas = vname.split('|')[0]
                mas = macro_inv[micro2macro['MicroAttackStage.'+mas]]
                shape = shapes[mas]
                if shape == shapes[0] or vname.split('|')[2] in already_addressed: # if it's oval, we dont do anything because its not high-sev sink
                    lines.append((0,'"'+translate(vname)+'" [shape='+shape+']'))
                else:
                    sinkflag = False
                    for sink in sev_sinks:
                        if vname.endswith(sink):
                            sinkflag = True
                            break
                    if sinkflag:
                        lines.append((0,'"'+translate(vname)+'" [style="dotted", shape='+shape+']'))
                    else:
                        lines.append((0,'"'+translate(vname)+'" [shape='+shape+']'))
                # add tooltip
                lines.append((1, '"'+translate(vname)+'"'+' [tooltip="'+ "\n".join(signatures) +'"]'))
            lines.append((1000,'}'))

            for l in lines: # count vertices and edges
                if '->' in l[1]:
                    edges +=1
                elif 'shape=' in l[1]:
                    vertices +=1
            simple[int_victim+'-'+AGname] = (vertices, edges)

            #print('# vert', vertices, '# edges: ', edges,  'simplicity', vertices/float(edges))
            if SAVE:
                out_f_name = datafile+'-attack-graph-for-victim-'+int_victim+'-'+AGname
                f = open(dirname+'/'+ out_f_name +'.dot', 'w')
                for l in lines:
                    f.write(l[1])
                    f.write('\n')
                f.close()

                os.system("dot -Tpng "+dirname+'/'+out_f_name+".dot -o "+dirname+'/'+out_f_name+".png")
                #os.system("dot -Tsvg "+dirname+'/'+out_f_name+".dot -o "+dirname+'/'+out_f_name+".svg")
                if DOCKER:
                    os.system("rm "+dirname+'/'+out_f_name+".dot")
                #print('~~~~~~~~~~~~~~~~~~~~saved')
            print('#', sep=' ', end=' ', flush=True)
        #print('total high-sev states:', len(path_info))
        #path_info = dict(sorted(path_info.items(), key=lambda kv: kv[0]))
        #for attackerID,v in path_info.items():
        #    print(attackerID)
        #    for t,val in v.items():
        #       print(t, val)
    #for attackerID,v in ser_total.items():
    #    print(attackerID, len(v), set([x.split('|')[0] for x in v]))


def setup_logging(logfile):
    fh = logging.FileHandler(logfile, 'w')
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)

    formatter = logging.Formatter('%(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)


# part 1, load spdfa
# tracefile = '/Users/ionbabalau/uni/thesis/SAGE/pred_traces/traces_team125.txt'
# modelfile = tracefile + '.ff.final.json'
# sinkfile = tracefile + '.ff.finalsinks.json'
#os.system("dot -Tpng " + tracefile + ".ff.final.dot -o team125_spdfa.png")

logger = logging.getLogger('mylogger')
logger.setLevel(logging.DEBUG)

setup_logging('out.log')

# part 2, load alert data set and simulate streaming
# time interval to remove duplicates
t = 1
w = 150
batch_interval_sec = 300
traces_rt_file = '/Users/ionbabalau/uni/thesis/SAGE/traces/traces_rt.txt'
modelfile = traces_rt_file + '.ff.final.json'
sinkfile = traces_rt_file + '.ff.finalsinks.json'

flexfringe_path = '/Users/ionbabalau/uni/thesis/FlexFringe'
known_traces = parse_file('/Users/ionbabalau/uni/thesis/SAGE/pred_traces/traces_team125.txt')
(alerts, team_labels) = load_data('/Users/ionbabalau/uni/thesis/SAGE/alerts_rt', t) # t = minimal window for alert filtering
print(len(alerts[0]))
print(team_labels)
alerts = alerts[0]
# create alert grouping
alerts.sort(key=lambda x: x[8])


#plot_alert_num_time(alerts, '2.5T')
batched_alerts = []

# Define the start time
start_time = alerts[0][8]

# Create an empty sublist for the first minute
group = []

for alert in alerts:
    if (alert[8] - start_time).total_seconds() < batch_interval_sec:
        group.append(alert)
    else:
        # Otherwise, add the group to the list and start a new group
        batched_alerts.append(group)
        group = [alert]
        # Update the start time
        start_time = alert[8]

# Add the final group to the list
batched_alerts.append(group)
print(len(batched_alerts), 'batches of alerts')
all_condensed_data = {}
predicted_eps = {}
current = []
condensed_data = dict()
total_pred = 0
tp = 0
tp_as = 0
wrong_pred = 0
low_pred = 0
med_pred = 0
high_pred = 0

for batch_no, batch in enumerate(batched_alerts):
    current.extend(batch)
    team_episodes, _ = aggregate_into_episodes([current], team_labels, step=w)
    host_data = host_episode_sequences(team_episodes)
    (alerts, keys) = break_into_subbehaviors(host_data)
    # before generating traces, predict next actions for ESS ending in non high AS
    logger.debug(f'batch {batch_no}')
    #write_traces_to_file(traces, '/Users/ionbabalau/uni/thesis/SAGE/traces/traces_rt.txt')
    rt_traces = generate_traces(alerts, keys, traces_rt_file)
    run_flexfringe(traces_rt_file, ini='/Users/ionbabalau/uni/thesis/SAGE/docker_stuff/spdfa-config.ini')
    fix_syntax(modelfile)
    fix_syntax(sinkfile)
    m, data = loadmodel(modelfile)
    m2, data2 = loadmodel(sinkfile)
    #os.system("dot -Tpng " + traces_rt_file + ".ff.final.dot -o /Users/ionbabalau/uni/thesis/SAGE/traces/rt_spdfa.png")
    
    (traces, state_traces) = encode_sequences(m, m2, traces_rt_file)
    (med_states, sev_states, sev_sinks) = find_severe_states(traces, m, m2)

    for k, eps in condensed_data.items():
        if k not in all_condensed_data:
            all_condensed_data[k] = set()
        for ep in eps:
            all_condensed_data[k].add((ep[0], ep[2]))
        
    
    for k in condensed_data:
        condensed_data[k] = []

    condensed_data = make_condensed_data(alerts, keys, state_traces, med_states, sev_states, condensed_data)

    for host, eps in condensed_data.items():
        if host not in all_condensed_data.keys():
            logger.debug(f'NEW HOST {host}')
        else:
            logger.debug(f'HOST {host}')
        new_high_found = False
        for i, ep in enumerate(eps):
            if host in all_condensed_data and (ep[0], ep[2]) not in all_condensed_data[host] and len(str(ep[2])) == 3:
                logger.debug('NEW HIGH SEVERITY EPISODE ' + str(micro[ep[2]].split('.')[1]) + ' for host ' + host)
                new_high_found = True
            elif host not in all_condensed_data and len(str(ep[2])) == 3:
                logger.debug(f'NEW HIGH SEVERITY EPISODE {micro[ep[2]].split(".")[1]} for NEW HOST {host}')
                new_high_found = True

        #if new_high_found:
        for i, ep in enumerate(eps):
            if ep[1] == -1:
                if len(str(rev_smallmapping[ep[2].split('|')[0]])) == 3:
                    logger.debug(f'PREDICTED HIGH SEV EPISODE {i} action {ep[2]} prob {ep[3]}')
                else:
                    logger.debug(f'PREDICTED EPISODE {i} action {ep[2]} prob {ep[3]}')
                predicted_eps[host] = (i, ep[2])
                if len(str(rev_smallmapping[ep[2].split('|')[0]])) == 3:
                    high_pred += 1
                elif len(str(rev_smallmapping[ep[2].split('|')[0]])) == 2:
                    med_pred += 1
                else:
                    low_pred += 1
            elif host in all_condensed_data and (ep[0], ep[2]) not in all_condensed_data[host]:
                logger.debug('NEW EPISODE ' + str(i) + ' start/end times ' + str(ep[0]) + ' ' + str(ep[1]) + ' mcat ' + micro[ep[2]].split('.')[1] + ' service ' + ep[4] + ' STATE ID ' + str(ep[3]))
                if host in predicted_eps.keys() and i == predicted_eps[host][0]:
                    logger.debug(f'CURRENT PREDICTION {predicted_eps[host]}')
                    pred = predicted_eps[host][1].split('|')[0]
                    pred_serv = predicted_eps[host][1].split('|')[1]
                    actual = small_mapping[ep[2]]
                    actua_serv = ep[4]
                    if pred == actual and pred_serv == actua_serv:
                        logger.debug(f'AS AND SERV MATCH')
                        tp += 1
                        tp_as += 1
                    elif pred == actual:
                        logger.debug(f'AS MATCH')
                        tp_as += 1
                        wrong_pred += 1
                    else:
                        logger.debug('WRONG PRED')
                        wrong_pred += 1
                    if len(str(ep[2])) == 3:
                        logger.debug('HIGH EP PREDICTION')
            else:
                logger.debug('EPISODE ' + str(i) + ' start/end times ' + str(ep[0]) + ' ' + str(ep[1]) + ' mcat ' + micro[ep[2]].split('.')[1] + ' service ' + ep[4] + ' STATE ID ' + str(ep[3]))
        logger.debug('\n')
    # logger.debug("EP SUBSEQUCES")
    # for k, eps in zip(keys, alerts):
    #     logger.debug(k)
    #     for i, ep in enumerate(eps):
    #         logger.debug('EPISODE ' + str(i) + ' start/end times ' + str(ep[0]) + ' ' + str(ep[1]) + ' mcat ' + micro[ep[2]].split('.')[1])
    # logger.debug("EP SUBSEQUCES END")
         

    #(condensed_a_data, condensed_v_data) = make_av_data(condensed_data)
    #make_AG(condensed_v_data, condensed_data, None, sev_sinks, 'traces_rt.txt', '/Users/ionbabalau/uni/thesis/SAGE/traces/', batch_no)
    #logger.debug(f'PREDICTED DICT {predicted_eps}')
    # if batch_no == 40:
    #     break

logger.debug(f'CORRECTLY PREDICTED {tp}, CORRECTLY PREDICTED AS ONLY {tp_as}, WRONG PREDS {wrong_pred}')
logger.debug(f'ACCURACY {tp/(tp + wrong_pred)}')
logger.debug(f'ACCURACY AS {tp_as/(tp_as + wrong_pred)}')
logger.debug(f'low {low_pred} med {med_pred} high {high_pred}')