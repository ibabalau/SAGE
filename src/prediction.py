import time
import os,re,operator, json, datetime, glob
import statistics 
import random
import seaborn as sns
import pandas as pd
import requests
import csv
import os.path
import matplotlib.pyplot as plt 
import itertools
import numpy as np
from numpy import diff
from pandas import DataFrame
import math
from itertools import accumulate
import matplotlib.style
import matplotlib as mpl
mpl.style.use('default')
import subprocess
import sys
import graphviz
from shutil import copyfile
from collections import defaultdict
import copy
import queue


def parse_file(f):
    fi = open(f, 'r')
    lines = fi.readlines()
    traces = []
    for lid, line in enumerate(lines):
        if lid == 0:
            continue
        sym = (line[:-1]).split(' ')
        traces.append(sym[2:])
    return traces


def flexfringe(*args, **kwargs):
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

def loadmodel(modelfile):

    '''Wrapper to load resulting model json file

    Keyword arguments:
    modelfile -- path to the json model file
    '''  

    # because users can provide unescaped new lines breaking json conventions
    # in the labels, we are removing them from the label fields
    with open(modelfile) as fh:
        data = fh.read()
    
    
    data = data.replace('\n', '').replace(',,', ',')#.replace(', ,', ',')#.replace('    ', ' ')
    data = re.sub( r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', data )

    data = re.sub(',+', ',', data)
    machine = json.loads(data)


    dfa = defaultdict(lambda: defaultdict(str))

    for edge in machine['edges']:
        dfa[ edge['source'] ][ edge['name'] ] = (edge['target'], edge['appearances'])

    for entry in machine['nodes']:
        dfa[ str(entry['id']) ]['type'] = '0'
        dfa[str(entry['id']) ]['isred'] = int(entry['isred'])

    return (dfa, machine)

def traverse(dfa, sinks, sequence, statelist=False):
    '''Wrapper to traverse a given model with a string

    Keyword arguments:
    dfa -- loaded model
    sequence -- space-separated string to accept/reject in dfa
    '''  
    #print(dfa)
    #in_main_model = set()
    sev_sinks = set()
    state = '0'
    stlst = ['0']
    #print('This seq', sequence.split(' '))
    for event in sequence.split(' '):
        sym = event.split(':')[0]
        
        #print('curr symbol ', sym, 'state no.', dfa[state][sym]) 
        
        state = dfa[state][sym]
        isred = 0
        
        if state != '':
            isred = dfa[state[0]]['isred']
        #print(state)
        #if state != '':
        #if isred == 1:
        #      in_main_model.add(state[0])
        if state == '':
            try:
                state = sinks[stlst[-1]][sym][0]
                sev_sinks.add(state)
            except:
                #print('didnt work for', sequence, 'done so far:', stlst)
                state = '-1'

            #print('Must look in sinks')
            #print('prev symb: ', sym, 'and prev state no.', stlst[-1])
            #print('BUT this last state no in sink gives ', sinks[stlst[-1]][sym])
            #print('curr sym', sym)
            #print('previous state no.:', stlst[-1], 'results in sink id:', sinks[stlst[-1]][sym] )
            #if sinks[stlst[-1]][sym] == '':
                    
                    #print('prob')
                    #print(sequence)
                    #state = '-1'
            #else:
            #      state = sinks[stlst[-1]][sym][0]
            #
            #if not statelist:
            #        return dfa[state]['type'] == '1'
            #else:
            #        return (dfa[state]['type'] == '1', stlst)

        else:
            try:
                #print('weird place')
                # take target id, discard counts
                state = state[0]
            except IndexError:
                print('Out of alphabet: alternatives')
            
                stlst.append('-1')
                if not statelist:
                        return dfa[state]['type'] == '1'
                else:
                        return (dfa[state]['type'] == '1', stlst)
        stlst.append(state)
    if not statelist:
        return dfa[state]['type'] == '1'
    else:
        return (dfa[state]['type'] == '1', stlst)

# total_fail_start_symb = 0
# total_fail_next_symb = 0
# total_fail_no_trans_pos = 0
# total_succ_root_node = 0
# total_succ_entire_path = 0
# cnt = cnt
from sklearn.utils import shuffle
from sklearn.preprocessing import normalize

def create_train_test_traces(trace_file, use_random = False, pdfa = False):
    traces = parse_file(trace_file)
    trainlen, testlen = round(len(traces)*0.8), round(len(traces)*0.2)
    if use_random:
        traces = shuffle(traces)
    if pdfa:
        for trace in traces:
            trace.reverse()
    train_data = traces[:trainlen]
    test_data = traces[trainlen:]
    print('Using', len(train_data), 'traces for training')
    print('Using', len(test_data), 'traces for testing')

    count_lines = 0
    count_cats = set()

    # create new train_traces file
    trace_file_name =  'train_traces.txt'
    trace_file_location = dir_path + '/pred_traces/'
    f = open(trace_file_location + trace_file_name, 'w')
    lines = []
    for i,trace in enumerate(train_data):
        count_lines += 1
        multi = trace
        for e in multi:
            count_cats.add(e)
        st = '1' + ' '+ str(len(multi)) + ' ' + ' '.join(multi) + '\n'
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()

    test_file_name =  'test_traces.txt'
    count_lines = 0
    count_cats = set()
    trace_file_location = dir_path + '/pred_traces/'
    f = open(trace_file_location + test_file_name, 'w')
    lines = []
    done_traces = set()
    test_data_uniq = []
    for i,trace in enumerate(test_data):
        str_trace = ''.join(trace)
        if str_trace in done_traces:
            continue
        else:
            done_traces.add(str_trace)
            test_data_uniq.append(trace)
        count_lines += 1
        multi = trace
        for e in multi:
            count_cats.add(e)
        st = '1' + ' '+ str(len(multi)) + ' ' + ' '.join(multi) + '\n'
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()
    return trace_file_location + trace_file_name, train_data, test_data_uniq

def fix_syntax(fname, is_sink_file = False):
    if is_sink_file:
        fname = fname + '.ff.finalsinks.json'
    else:
        fname = fname + '.ff.final.json'
    print('--- Main')
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


def create_structs(data, unique_sym):
    # spdfa['node_id'] -> {'total_cnt', 'symbol', 'fin', 'paths', 'transitions' = {'symbol': {'dnode', 'count'}}}
    spdfa = {}
    for node in data['nodes']:
        if node['data']['total_paths'] > 0:
            spdfa[str(node['id'])] = {'total_cnt': node['size'], 'symbol': '', 'fin': node['data']['total_final'], 'paths': node['data']['total_paths'], 'transitions': {k: int(v) for k,v in dict(node['data']['trans_counts']).items() if int(v) != 0}}
        else:
            spdfa[str(node['id'])] = {'total_cnt': node['size'], 'symbol': '', 'fin': node['data']['total_final'], 'paths': 0, 'transitions': {}}

    for edge in data['edges']:
        spdfa[edge['source']]['transitions'][edge['name']] = {'dnode': edge['target'], 'count': spdfa[edge['source']]['transitions'][edge['name']]}
        spdfa[edge['target']]['symbol'] = edge['name']

    nodes = [str(x['id']) for x in data['nodes']]
    edges = [x['name'] for x in data['edges']]

    total_symb_cnt = {key: 0 for key in unique_sym}
    for trace in train_data:
        for item in trace:
            total_symb_cnt[item] += 1

    end_symb_cnt = {key: 0 for key in unique_sym}
    for _, item in spdfa.items():
        if item['symbol'] == '':
            continue
        end_symb_cnt[item['symbol']] += item['fin']

    # used for finding starting nodes of a symbol
    symbol_to_state = {key: set() for key in unique_sym}

    # reverse spdfa, dict where key is a node, value is a list of transitions to parent nodes, together with their probabilities
    rev_spdfa = {key: {'symbol': spdfa[key]['symbol'], 'transitions':[]} for key in nodes}

    for edge in data['edges']:
        snode = edge['source']
        dnode = edge['target']
        symbol = edge['name']
        #print(snode, dnode, symbol, spdfa[snode]['fin'])
        if spdfa[dnode]['fin'] != 0:
            ending_prob = (spdfa[snode]['transitions'][symbol]['count'] / spdfa[dnode]['total_cnt']) * spdfa[dnode]['fin'] / end_symb_cnt[symbol]
        else:
            ending_prob = 0
        prob = (spdfa[snode]['transitions'][symbol]['count'] / spdfa[dnode]['total_cnt']) #* spdfa[snode]['transitions'][symbol]['count']/total_symb_cnt[symbol]
        rev_spdfa[dnode]['transitions'].append({'target': snode, 'prob': prob, 'ending_prob': ending_prob})
        symbol_to_state[symbol].add(dnode)
    return spdfa, rev_spdfa, symbol_to_state

def find_probabilities(rev_spdfa, start_nodes, trace):
    # q.put and q.get
    q = queue.Queue()
    final_probs = []
    no_symbol_cnt = 0
    no_trans_cnt = 0
    for node in start_nodes:
        q.put((node, trace, []))
    while not q.empty():
        node, tr, pr_list = q.get()
        print('current node', node, 'trace', tr, 'prob list', pr_list)
        if tr == []:
            # end of trace reached, do stuff
            print('end of trace reached')
            final_probs.append((pr_list, rev_spdfa[node]['symbol']))
            continue
        current_symb = tr[0]
        # check next transitions
        if current_symb == rev_spdfa[node]['symbol']:
            for item in rev_spdfa[node]['transitions']:
                # if first symbol, use ending prob, otheriwse normal prob
                if tr == trace:
                    q.put((item['target'], tr[1:], pr_list + [(node + '->' + item['target'], item['ending_prob'])]))
                else:
                    q.put((item['target'], tr[1:], pr_list + [(node + '->' + item['target'], item['prob'])]))
        elif rev_spdfa[node]['symbol'] == '':
            no_trans_cnt += 1
        else:
            no_symbol_cnt += 1
            current_as = current_symb.split('|')[0]
            actual_as = rev_spdfa[node]['symbol'].split('|')[0]
            if current_as == actual_as:
                ind = np.argmax([item['prob'] for item in rev_spdfa[node]['transitions']])
                q.put((rev_spdfa[node]['transitions'][ind]['target'], tr[1:], pr_list + [(node + '->' + rev_spdfa[node]['transitions'][ind]['target'], rev_spdfa[node]['transitions'][ind]['prob'])]))
    return final_probs, 0 if no_symbol_cnt > no_trans_cnt else 1

from enum import Enum
class Strategy(Enum):
    FULL_MATCH = 1
    AS_MATCH = 2
    ALL = 3


def find_probabilities_fuzzing(rev_spdfa, start_nodes, trace, use_factor, strategy = Strategy.ALL):
    # q.put and q.get
    q = queue.Queue()
    final_probs = []
    found_symbol = [0 for x in range(len(trace))]
    found_symbol[0] = 1
    prob_to_redis = []
    for node in start_nodes:
        q.put((node, trace, [], 1))
    counter = {}
    cnt = 0
    while not q.empty():
        cnt += 1
        node, tr, path, prob = q.get()
        key = (node, frozenset(tr))
        if key in counter:
            counter[key] += 1
        else:
            counter[key] = 1
        factor = 1
        #print('current node', node, 'trace', tr, 'prob list', pr_list)
        if not tr:
            # end of trace reached, do stuff
            #print('end of trace reached')
            final_probs.append((prob, path, rev_spdfa[node]['symbol']))
            continue
        current_symb = tr[0]
        # check next transitions
        if rev_spdfa[node]['symbol'] == '':
            prob_to_redis.append(prob)
        else:
            current_as = current_symb.split('|')[0]
            actual_as = rev_spdfa[node]['symbol'].split('|')[0]
            if use_factor:
                if current_symb == rev_spdfa[node]['symbol']:
                    factor = 50
                elif current_as == actual_as:
                    factor = 25
            if current_symb == rev_spdfa[node]['symbol'] or current_as == actual_as:
                found_symbol[len(trace) - len(tr)] = 1
            # if first symbol, use ending prob, otheriwse normal prob
            if tr == trace:
                prob_key = 'ending_prob'
            else:
                prob_key = 'prob'

            if strategy == Strategy.FULL_MATCH:
                if current_symb == rev_spdfa[node]['symbol']:
                    for item in rev_spdfa[node]['transitions']:
                        q.put((item['target'], tr[1:], path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']], prob * item[prob_key] * factor))
                else:
                    prob_to_redis.append(prob)
            elif strategy == Strategy.AS_MATCH:
                if current_symb == rev_spdfa[node]['symbol'] or current_as == actual_as:
                    for item in rev_spdfa[node]['transitions']:
                        q.put((item['target'], tr[1:], path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']], prob * item[prob_key] * factor))
                else:
                    prob_to_redis.append(prob)
            else:
                for item in rev_spdfa[node]['transitions']:
                    q.put((item['target'], tr[1:], path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']], prob * item[prob_key] * factor))
    
    sorted_pairs = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:20]
    print('total', cnt)
    for i in sorted_pairs:
        print(i)
    return final_probs, prob_to_redis


def find_probabilities_fuzzing_dfs(rev_spdfa, start_nodes, trace, use_factor, strategy = Strategy.ALL, final_probs = [], prob_to_redis = []):
    if trace == []:
        # end of trace reached, do stuff
        final_probs.append((prob, path, rev_spdfa[node]['symbol']))
    factor = 1
    current_symb = tr[0]
    # check next transitions
    if rev_spdfa[node]['symbol'] == '':
        prob_to_redis.append(prob)
    else:
        current_as = current_symb.split('|')[0]
        actual_as = rev_spdfa[node]['symbol'].split('|')[0]
        if use_factor:
            if current_symb == rev_spdfa[node]['symbol']:
                factor = 50
            elif current_as == actual_as:
                factor = 25
        if current_symb == rev_spdfa[node]['symbol'] or current_as == actual_as:
            found_symbol[len(trace) - len(tr)] = 1
        # if first symbol, use ending prob, otheriwse normal prob
        if tr == trace:
            prob_key = 'ending_prob'
        else:
            prob_key = 'prob'

        if strategy == Strategy.FULL_MATCH:
            if current_symb == rev_spdfa[node]['symbol']:
                for item in rev_spdfa[node]['transitions']:
                    q.put((item['target'], tr[1:], path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']], prob * item[prob_key] * factor))
            else:
                prob_to_redis.append(prob)
        elif strategy == Strategy.AS_MATCH:
            if current_symb == rev_spdfa[node]['symbol'] or current_as == actual_as:
                for item in rev_spdfa[node]['transitions']:
                    q.put((item['target'], tr[1:], path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']], prob * item[prob_key] * factor))
            else:
                prob_to_redis.append(prob)
        else:
            for item in rev_spdfa[node]['transitions']:
                q.put((item['target'], tr[1:], path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']], prob * item[prob_key] * factor))


def test_pred_sum(spdfa, rev_spdfa, test_traces):
    tp_cnt = 0
    tp_as_cnt = 0
    skip_cnt = 0
    no_start_cnt = 0
    fin_tt = []
    for test_trace in test_traces:
        if len(test_trace) < 8 and test_trace[0] in symbol_to_state:
            fin_tt.append(test_trace)
    fin_tt = sorted(fin_tt, key=len)
    print(len(fin_tt))
    fin_tt = [['serD|ssh', 'serD|ssh', 'serD|unknown', 'vulnD|postgresql']]
    fin_tt[0].reverse()
    #test_trace = ['vulnD|ahsp', 'serD|unknown', 'vulnD|postgresql', 'serD|unknown', 'vulnD|ahsp', 'vulnD|ahsp', 'vulnD|postgresql', 'vulnD|postgresql', 'serD|unknown', 'serD|cm', 'vulnD|ahsp', 'vulnD|ahsp', 'serD|ag-swim', 'vulnD|ms-sql-s']
    for test_trace in fin_tt:
        test_trace.reverse()
        true_action = test_trace[-1]
        test_trace = test_trace[:-1]
        print('---------------------------TESTING----------------------------')
        print('reversed input trace:', test_trace, 'LENGHT', len(test_trace))
        start_nodes = list(symbol_to_state[test_trace[0]])
        # optimization: remove starting nodes where starting prob is 0, cause entire trace is gonna be 0 anyway
        start_nodes = [node for node in start_nodes if spdfa[node]['fin'] != 0]
        if start_nodes == []:
            no_start_cnt += 1
            continue
        print('starting nodes', start_nodes)
        
        strat = Strategy.ALL
        use_scaling = True
        start_time = time.time()
        prob_list, prob_to_redistribute = find_probabilities_fuzzing(rev_spdfa, start_nodes, test_trace, use_scaling, strat)
        print('EXECUTION TIME', time.time() - start_time, 'seconds')
        print('FOUND', len(prob_list), 'PATHS AND ', len(prob_to_redistribute), 'WHICH END IN ROOT')
        if prob_list == []:
            skip_cnt += 1
            print('NO PATH FOUND')
            continue
        # normalization
        probs_to_scale = [probs for probs, _, _ in prob_list]
        if prob_to_redistribute != []:
            probs_to_scale += prob_to_redistribute
        s =  np.sum(probs_to_scale)
        normalized = [x/s for x in probs_to_scale]
        probs_multiplied = normalized[:len(prob_list)]
        
        # redistribution
        total_red = 0
        if prob_to_redistribute != []:
            prob_to_redistribute = normalized[-len(prob_to_redistribute):]
            probs_sum = np.sum(probs_multiplied) + np.sum(prob_to_redistribute)
            #print('PROB SUM', probs_sum)
            if probs_sum < 0.99 or probs_sum > 1.01:
                print('ERR')
                exit()
            total_red = np.sum(prob_to_redistribute)/len(prob_list)
        
        # finding next action
        next_actions = {}
        for prob, path, na in prob_list:
            prob += total_red
            if na in next_actions:
                next_actions[na] += prob
            else:
                next_actions[na] = prob
        sorted_pairs = sorted(next_actions.items(), key=lambda x: x[1], reverse=True)[:5]
        # print('top 5 actions')
        # for i in sorted_pairs:
        #     print(i)
        print('PREDICTED ACTION', sorted_pairs[0])
        print('TRUE ACTION', true_action)
        pred = sorted_pairs[0]
        if pred[0] == true_action:
            tp_cnt += 1
            tp_as_cnt += 1
        elif get_attack_stage(pred[0]) == get_attack_stage(true_action):
            tp_as_cnt += 1
        print('--------------------------------------------------------------\n')
    final_len = len(fin_tt)
    print('skipped', skip_cnt)
    print('no start after opti', no_start_cnt)
    print('tested on ', final_len, 'traces')
    return tp_cnt/final_len, tp_as_cnt/final_len
    
def get_attack_stage(symbol):
    return symbol.split('|')[0]


def find_path(pdfa, trace):
    node = '0'
    prob = 1
    for symbol in trace:
        print('symbol', symbol, 'node', node)
        true_as = get_attack_stage(symbol)
        if symbol in pdfa[node]['transitions']:
            prob *= pdfa[node]['transitions'][symbol]['count']/pdfa[node]['paths']
            node = pdfa[node]['transitions'][symbol]['dnode']
        else:
            flag = 0
            for poss_symb in pdfa[node]['transitions'].keys():
                a_stage = get_attack_stage(poss_symb)
                if a_stage == true_as:
                    prob *= pdfa[node]['transitions'][poss_symb]['count']/pdfa[node]['paths']
                    node = pdfa[node]['transitions'][poss_symb]['dnode']
                    flag = 1
                    break
            if flag == 0:
                print('cant follow trace anymore')
                return 0, None
    return prob, node

def test_pdfa(pdfa, test_traces):
    # pdfa['node_id'] -> {'total_cnt', 'symbol', 'fin', 'paths', 'transitions' = {'symbol': {'dnode', 'count'}}}
    test_trace = ['serD|ssh', 'serD|ssh', 'serD|unknown']
    tp_cnt = 0
    tp_as_cnt = 0
    final_len = len(test_traces)
    path_not_found = 0
    no_more_action = 0
    for tt in test_traces:
        true_action = tt[-1]
        tt = tt[:-1]
        prob, node = find_path(pdfa, tt)
        if node == None:
            path_not_found += 1
            continue
        sorted_pairs = sorted(pdfa[node]['transitions'].items(), key=lambda x: x[1]['count'], reverse=True)[:5]
        print('top 5 actions')
        for i in sorted_pairs:
            print(i)
        print('TRUE ACTION', true_action)
        if sorted_pairs == []:
            no_more_action += 1
            continue
        pred = sorted_pairs[0]
        if pred[0] == true_action:
            tp_cnt += 1
            tp_as_cnt += 1
        else:
            current_as = pred[0].split('|')[0]
            actual_as = true_action.split('|')[0]
            if current_as == actual_as:
                tp_as_cnt += 1
    print(no_more_action)
    print(path_not_found)
    print('Accuracy:', tp_cnt/final_len)
    print('Accuracy with AS:', tp_as_cnt/final_len)
    return
    

dir_path = '/Users/ionbabalau/uni/thesis/SAGE'
flexfringe_path = '/Users/ionbabalau/uni/thesis/FlexFringe'
output_path = '/Users/ionbabalau/uni/thesis/SAGE/output_pred'
tr_file_name = dir_path + '/pred_traces/trace_all.txt'
USE_SINKS = True

### MAIN START ###
acc_total = 0
acc_as_total = 0
cnt = 1
use_rand = False
for i in range(cnt):
    full_model_name, train_data, test_data = create_train_test_traces(tr_file_name, use_rand)
    unique_sym = set([item for sublist in train_data for item in sublist])

    if USE_SINKS:
        path_to_ini = flexfringe_path + '/ini/spdfa-config-sinks.ini'
    else:
        path_to_ini = flexfringe_path + '/ini/spdfa-config.ini'

    print('------ Learning SPDFA ---------')
    # Learn S-PDFA
    flexfringe(full_model_name, ini=path_to_ini)

    #os.system('dot -Tpng ' + full_model_name + '.ff.final.dot -o ' + output_path + '/main_model.png')

    fix_syntax(full_model_name)

    print('------ Loading and traversing SPDFA ---------')
    model, data = loadmodel(full_model_name + '.ff.final.json')
    os.system('cp ' + full_model_name + '.ff.final.json ' + output_path + '/main.json')
    os.system('cp ' + full_model_name + '.ff.finalsinks.json '+ output_path + '/sinks.json')

    spdfa, rev_spdfa, symbol_to_state = create_structs(data, unique_sym)
    acc, acc_as = test_pred_sum(spdfa, rev_spdfa, test_data)
    acc_total += acc
    acc_as_total += acc_as
print('Accuracy', acc_total/cnt)
print('Accuracy with AS', acc_as_total/cnt)

