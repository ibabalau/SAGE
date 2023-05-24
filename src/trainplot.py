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
from sklearn.model_selection import KFold

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


def create_train_test_traces(train_data, test_data):#trace_file, use_random = False, pdfa = False):
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
    for i,trace in enumerate(test_data):
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
    return trace_file_location + trace_file_name

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


def create_structs(train_data, data, unique_sym):
    global total_edges
    global total_nodes
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
    total_nodes[len(train_data)].append(len(nodes))
    edges = [x['name'] for x in data['edges']]
    total_edges[len(train_data)].append(len(edges))

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
    BASELINE_RAND = 4
    BASELINE_PROB = 5
    FULL_MATCH = 1
    AS_MATCH = 2
    ALL = 3

class Metric(Enum):
    ACCURACY = 1
    ACCURACY_AS = 2
    SKIP_CNT = 3
    EXEC_TIME = 4


def traverse_pnfa_bfs(rev_spdfa, start_nodes, trace, use_factor, strategy = Strategy.ALL):
    # q.put and q.get
    q = queue.Queue()
    final_probs = []
    found_symbol = [0 for x in range(len(trace))]
    found_symbol[0] = 1
    prob_to_redis = []
    for node in start_nodes:
        q.put((node, trace, [], 1))
    while not q.empty():
        node, tr, path, prob = q.get()
        factor = 1
        #print('current node', node, 'trace', tr, 'prob list', pr_list)
        if not tr:
            # end of trace reached, do stuff
            #print('end of trace reached')
            final_probs.append((path, prob, rev_spdfa[node]['symbol']))
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
    
    return final_probs, prob_to_redis


memo = {}
as_to_sev = {
    'tarID':'LOW',
    'surf':'LOW',
    'hostD':'LOW',
    'serD':'LOW',
    'vulnD':'LOW',
    'infoD':'LOW',
    'uPrivEsc':'MEDIUM',
    'rPrivEsc':'MEDIUM',
    'netSniff':'MEDIUM',
    'bfCred':'MEDIUM',
    'acctManip':'MEDIUM',
    'TOexp':'MEDIUM',
    'PAexp':'MEDIUM',
    'remoteexp':'MEDIUM',
    'sPhish':'MEDIUM',
    'servS':'MEDIUM',
    'evasion':'MEDIUM',
    'CnC':'MEDIUM',
    'lateral':'MEDIUM',
    'ACE':'MEDIUM',
    'privEsc':'MEDIUM',
    'endDOS':'HIGH',
    'netDOS':'HIGH',
    'serStop':'HIGH',
    'resHJ':'HIGH',
    'dDestruct':'HIGH',
    'cWipe':'HIGH',
    'dEncrypt':'HIGH',
    'deface':'HIGH',
    'dManip':'HIGH',
    'exfil':'HIGH',
    'delivery':'HIGH',
}

def traverse_pnfa_dfs(rev_spdfa, state, trace, len_traces, use_factor, strategy = Strategy.ALL):
    key = (state, tuple(trace))
    #print('KEY', key)
    #if key in memo:
    #    return memo[key]
    
    paths = []
    if not trace:
        #print('trace finished, returning')
        return [(None, 1.0, rev_spdfa[state]['symbol'] if rev_spdfa[state]['symbol'] != '' else 'None')]

    symbol = trace[0]
    factor = 1
    prob_key = 'prob'
    current_as = symbol.split('|')[0]
    actual_as = rev_spdfa[state]['symbol'].split('|')[0]
    if rev_spdfa[state]['symbol'] == '':
        #print('root node reached, returning')
        return [(None, 1.0, 'FAIL')]
    else:
        if use_factor:
            if symbol == rev_spdfa[state]['symbol']:
                factor = 50
            elif current_as == actual_as:
                factor = 25
        # first symbol -> use ending prob instead
        if len(trace) == len_traces:
            prob_key = 'ending_prob'

    #print('current symbol', symbol)
    trans = []
    if strategy == Strategy.FULL_MATCH:
        if rev_spdfa[state]['symbol'] == symbol:
            trans = rev_spdfa[state]['transitions']
        else:
            return [(None, 1.0, 'FAIL')]
    elif strategy == Strategy.AS_MATCH:
        if rev_spdfa[state]['symbol'] == symbol or current_as == actual_as:
            trans = rev_spdfa[state]['transitions']
        else:
            return [(None, 1.0, 'FAIL')]
    else:
        trans = rev_spdfa[state]['transitions']
    next_states = [item['target'] for item in trans]
    next_probs = [item[prob_key] * factor for item in trans]

    for s, p in zip(next_states, next_probs):
        for path, prob, next_action in traverse_pnfa_dfs(rev_spdfa, s, trace[1:], len_traces, use_factor, strategy):
            paths.append((None, p * prob, next_action))
    
    #memo[key] = paths
    #print('adding to memo and returning, key', key)
    return paths

def test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, strat, train_len):
    global exectimes_dict
    global result_dict
    memo.clear()
    skip_cnt = 0
    total_stime = time.time()
    y_pred = []
    for test_trace in X_test:
        #print('---------------------------TESTING----------------------------')
        #print('reversed input trace:', test_trace, 'LENGHT', len(test_trace))
        if test_trace[0] not in symbol_to_state:
            skip_cnt += 1
            y_pred.append('None')
            continue
        start_nodes = list(symbol_to_state[test_trace[0]])
        #print('starting nodes', start_nodes)
        use_scaling = True
        # final_paths, prob_to_redistribute = traverse_pnfa_bfs(rev_spdfa, start_nodes, test_trace, use_scaling, strat)
        # probs_to_scale = [x[1] for x in final_paths]
        prob_list = []
        prob_to_redistribute = []
        start_time = time.time()
        for snode in start_nodes:
            prob_list += traverse_pnfa_dfs(rev_spdfa, snode, test_trace, len(test_trace), use_scaling, strat)
        print('done traversing')
        exectimes_dict[strat][train_len].append(time.time() - start_time)
        #print('EXECUTION TIME', time.time() - start_time, 'seconds')
        if prob_list == []:
            skip_cnt += 1
            y_pred.append('None')
            continue
        # filter out incomplete paths
        final_paths = []
        probs_to_scale = []
        for path in prob_list:
            # n symbols means n + 1 nodes in the path, so we remove paths that are incomplete
            if path[2] == 'FAIL':#len(path[0]) != len(test_trace) + 1:
                prob_to_redistribute.append(path[1])
            else:
                final_paths.append(path)
                probs_to_scale.append(path[1])
        #print('FOUND', len(final_paths), 'PATHS AND', len(prob_to_redistribute), 'WHICH END IN ROOT')
        # if no possible paths are possible
        if len(final_paths) == 0:
            skip_cnt += 1
            y_pred.append('None')
            continue
        # normalization
        if prob_to_redistribute != []:
            probs_to_scale += prob_to_redistribute
        s =  np.sum(probs_to_scale)
        if s != 0:
            normalized = [x/s for x in probs_to_scale]
        else:
            normalized = probs_to_scale
        new_probs = normalized[:len(final_paths)]
        
        # redistribution
        total_red = 0
        if prob_to_redistribute != []:
            prob_to_redistribute = normalized[-len(prob_to_redistribute):]
            probs_sum = np.sum(new_probs) + np.sum(prob_to_redistribute)
            #print('PROB SUM', probs_sum)
            if s != 0 and probs_sum < 0.99 or probs_sum > 1.01:
                print('ERR')
                exit()
            total_red = np.sum(prob_to_redistribute)/len(final_paths)
        final_paths = [(final_paths[i][0], normalized[i] + total_red, final_paths[i][2]) for i in range(len(final_paths))]

        # finding next action
        # top5 = sorted(prob_list, key=lambda x:x[1], reverse=True)[:5]
        # print('top 5 paths')
        # for x in top5:
        #     print(x[0])
        next_actions = {}
        for path, prob, na in final_paths:
            if na in next_actions:
                next_actions[na] += prob
            else:
                next_actions[na] = prob
        sorted_pairs = sorted(next_actions.items(), key=lambda x: x[1], reverse=True)[:5]
        # print('top 5 actions')
        # for i in sorted_pairs:
        #     print(i)
        #print('PREDICTED ACTION', sorted_pairs[0])
        #print('TRUE ACTION', true_action)
        y_pred.append(sorted_pairs[0][0])
    exec_time = time.time() - total_stime
    y_pred_as = [get_attack_stage(symb) for symb in y_pred]
    print(Y_test, y_pred)
    result_dict[strat][Metric.ACCURACY].append(accuracy_score(Y_test, y_pred))
    result_dict[strat][Metric.ACCURACY_AS].append(accuracy_score(Y_test_as, y_pred_as))
    result_dict[strat][Metric.SKIP_CNT].append(skip_cnt/len(X_test))
    result_dict[strat][Metric.EXEC_TIME].append(exec_time)    
    return
    
def get_attack_stage(symbol):
    if symbol == 'None':
        return symbol
    else:
        return symbol.split('|')[0] #😂


def find_path(pdfa, trace):
    node = '0'
    q = queue.Queue()
    final_probs = []
    found_symbol = [0 for x in range(len(trace))]
    found_symbol[0] = 1
    prob_to_redis = []
    q.put((node, trace, node, 1))
    while not q.empty():
        node, tr, path, prob = q.get()
        if tr == []:
            final_probs.append((path, prob, pdfa[node]['transitions']))
            continue
        symbol = tr[0]
        true_as = get_attack_stage(symbol)
        if symbol in pdfa[node]['transitions']:
            dprob = pdfa[node]['transitions'][symbol]['count']/pdfa[node]['paths']
            dnode = pdfa[node]['transitions'][symbol]['dnode']
            q.put((dnode, tr[1:], path + '->' + dnode, prob * dprob * 50))
        else:
            found_as = 0
            for poss_symb in pdfa[node]['transitions'].keys():
                a_stage = get_attack_stage(poss_symb)
                if a_stage == true_as:
                    dprob = pdfa[node]['transitions'][poss_symb]['count']/pdfa[node]['paths']
                    dnode = pdfa[node]['transitions'][poss_symb]['dnode']
                    q.put((dnode, tr[1:], path + '->' + dnode, prob * dprob * 20))
                    found_as = 1
            if found_as == 0:
                for poss_symb in pdfa[node]['transitions'].keys():
                    dprob = pdfa[node]['transitions'][poss_symb]['count']/pdfa[node]['paths']
                    dnode = pdfa[node]['transitions'][poss_symb]['dnode']
                    q.put((dnode, tr[1:], path + '->' + dnode, prob * dprob))
    return final_probs

def test_pdfa(pdfa, test_traces):
    # pdfa['node_id'] -> {'total_cnt', 'symbol', 'fin', 'paths', 'transitions' = {'symbol': {'dnode', 'count'}}}
    test_trace = ['serD|ssh', 'serD|ssh', 'serD|unknown']
    accuracy_per_as = {'LOW':0, 'MEDIUM':0, 'HIGH':0}
    as_count = {'LOW':0, 'MEDIUM':0, 'HIGH':0}
    fin_tt = []
    for test_trace in test_traces:
        if test_trace[0] in symbol_to_state and len(test_trace) <= 7:
            fin_tt.append(test_trace)
    fin_tt = sorted(fin_tt, key=len)
    tp_cnt = 0
    tp_as_cnt = 0
    final_len = len(test_traces)
    path_not_found = 0
    no_more_action = 0
    for tt in fin_tt:
        true_action = tt[-1]
        tt = tt[:-1]
        final_probs = find_path(pdfa, tt)
        if final_probs == []:
            continue
        next_actions = {}
        final_paths = []
        for path, prob, trans in final_probs:
            # get next action
            sorted_pairs = sorted(trans.items(), key=lambda x: x[1]['count'], reverse=True)[:1]
            if sorted_pairs == []:
                final_paths.append((path, prob, 'None'))
            else:    
                final_paths.append((path, prob, sorted_pairs[0][0]))
        for path, prob, na in final_paths:
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
        if get_attack_stage(pred[0]) == get_attack_stage(true_action):
            accuracy_per_as[as_to_sev[get_attack_stage(true_action)]] += 1
        as_count[as_to_sev[get_attack_stage(true_action)]] += 1
    print(no_more_action)
    print(path_not_found)
    print('Accuracy:', tp_cnt/final_len)
    print('Accuracy with AS:', tp_as_cnt/final_len)
    return tp_cnt/final_len, tp_as_cnt/final_len
    
from sklearn.metrics import accuracy_score

def test_baseline(train_data, X_test, Y_test, Y_test_as, uniq_symbs):
    global result_dict
    probs = {symb: {next_symb: 0 for next_symb in uniq_symbs} for symb in uniq_symbs}
    for trace in train_data:
        for symbol, next_symbol in zip(trace, trace[1:]):
            probs[symbol][next_symbol] += 1
    next_actions = {symb: sorted(probs[symb].items(), key=lambda x: x[1], reverse=True)[:1][0][0] for symb in uniq_symbs}
    y_pred = []
    skip_cnt = 0
    for trace in X_test:
        last_action = trace[-1]
        if last_action in next_actions:
            predicted_action = next_actions[last_action]
            y_pred.append(predicted_action)
        else:
            skip_cnt += 1
            y_pred.append('None')
    y_pred_as = [get_attack_stage(symb) for symb in y_pred]
    result_dict[Strategy.BASELINE_PROB][Metric.ACCURACY].append(accuracy_score(Y_test, y_pred))
    result_dict[Strategy.BASELINE_PROB][Metric.ACCURACY_AS].append(accuracy_score(Y_test_as, y_pred_as))
    result_dict[Strategy.BASELINE_PROB][Metric.SKIP_CNT].append(skip_cnt/len(X_test))
    return

def test_baseline_rand(Y_test, Y_test_as):
    global result_dict
    last_symbols = set(Y_test)
    last_symbols_as = set(Y_test_as)
    result_dict[Strategy.BASELINE_RAND][Metric.ACCURACY].append(1/len(last_symbols))
    result_dict[Strategy.BASELINE_RAND][Metric.ACCURACY_AS].append(1/len(last_symbols_as))

def plot_values(xvalues, yvalues, xlabel, ylabel, title, filename):
    fig, ax = plt.subplots()
    # Plot the values

    lengths = yvalues
    unique_values, value_counts = np.unique(lengths, return_counts=True)
    for i in range(len(unique_values)):
        print(unique_values[i], value_counts[i])

    unique_lengths = max(set(lengths))
    print(unique_lengths)
    bin_edges = range(min(lengths), max(lengths) + 2)  # Add 1 for the last edge

    # Create the histogram
    fig, ax = plt.subplots()
    n, bins, patches = ax.hist(lengths, bins=bin_edges, edgecolor='black')

    # Set X-axis labels
    num_x_labels = 7
    x_label_indices = [i for i in range(min(set(lengths)), max(set(lengths)), 3)]
    x_label_indices.append(unique_lengths)  # Ensure the last label is included
    x_labels = [str(i) for i in x_label_indices]

    ax.set_xticks([0.5 + i for i in x_label_indices])
    ax.set_xticklabels(x_labels)

    #ax.plot(yvalues, linestyle='-', marker='o')
    # Set the title and axis labels
    ax.set_title(title, fontsize=13, fontfamily='serif')
    ax.set_xlabel(xlabel,  fontsize=12, fontfamily='serif')
    ax.set_ylabel(ylabel,  fontsize=12, fontfamily='serif')


    # Add a legend
    #ax.legend()

    # Save the plot as a PNG file in high-quality
    fig.savefig(filename, dpi=300)

dir_path = '/Users/ionbabalau/uni/thesis/SAGE'
flexfringe_path = '/Users/ionbabalau/uni/thesis/FlexFringe'
output_path = '/Users/ionbabalau/uni/thesis/SAGE/output_pred'
tr_file_name = dir_path + '/pred_traces/trace_all.txt'
USE_SINKS = True

to_plot = {strat:[] for strat in Strategy}
strategies = ['baseline_rand', 'baseline_prob', 'full_match', 'as_match', 'any_match']
result_dict = {strategy: {key:[] for key in Metric} for strategy in Strategy}

max_len = 6
cnt = 10
lens = [i for i in range(300, 501, 25)]
total_nodes = {key: [] for key in lens}
total_edges = {key: [] for key in lens}

exectimes_dict = {strategy: {key:[] for key in lens} for strategy in [Strategy.FULL_MATCH, Strategy.AS_MATCH, Strategy.ALL]}

from random import shuffle
for i in range(cnt):
    traces = parse_file(tr_file_name)
    shuffle(traces)
    unique_trace = [list(y) for y in set([tuple(x) for x in traces])]
    unique_trace = [x for x in unique_trace  if len(x) == max_len]
    shuffle(unique_trace)
    unique_length_lists = [unique_trace[random.randint(0, len(unique_trace) - 1)]]
    # lengths = set()
    # for lst in unique_trace:
    #     length = len(lst)
    #     if length not in lengths:
    #         lengths.add(length)
    #         unique_length_lists.append(lst)


    test_data = unique_length_lists
    train_data = []
    for trace in traces:
        if trace not in test_data:
            train_data.append(trace)
    print('TEST', test_data)
    test_data = sorted(test_data, key=len)
    for trace in test_data:
        trace.reverse()
    X_test = [trace[:-1] for trace in test_data]
    Y_test = [trace[-1] for trace in test_data]
    Y_test_as = [get_attack_stage(symb) for symb in Y_test]
    for train_len in lens:
        train_data_cur = train_data[:train_len]

        full_model_name = create_train_test_traces(train_data_cur, test_data)
        unique_sym = set([item for sublist in train_data_cur for item in sublist])

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

        spdfa, rev_spdfa, symbol_to_state = create_structs(train_data_cur, data, unique_sym)

        #test_baseline_rand(Y_test, Y_test_as)
        #test_baseline(train_data, X_test, Y_test, Y_test_as, unique_sym)
        test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, Strategy.FULL_MATCH, train_len)
        print('------------------------------------------')
        test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, Strategy.AS_MATCH, train_len)
        print('------------------------------------------')
        test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, Strategy.ALL, train_len)

        print()
        for strat in Strategy:
            print(strat)
            for metric in Metric:
                if len(result_dict[strat][metric]) != 0:
                    print(metric, sum(result_dict[strat][metric])/len(result_dict[strat][metric]))
                # if metric == Metric.ACCURACY:
                #     to_plot[strat].append(sum(result_dict[strat][metric])/len(result_dict[strat][metric]))
            print()

    #Create a figure and axis object
    # print(to_plot)

        #print('--------------------------------------------------------------\n')    
    
fig, ax = plt.subplots()

# Plot the values
for key,val in exectimes_dict.items():
    print(key)
    for k,sublist in val.items():
        print(k, sublist)
    y_values = [np.sum(sublist)/len(sublist) for k,sublist in val.items()]
    x_axis = [k for k, _ in val.items()]
    ax.plot(x_axis, y_values, label=key, linestyle='-', marker='o')

# Set the title and axis labels
ax.set_title('Execution time for different training dataset sizes', fontsize=13, fontfamily='serif')
ax.set_xlabel('Training set length', fontsize=12, fontfamily='serif')
ax.set_ylabel('Execution time, seconds', fontsize=12, fontfamily='serif')
ax.set_yscale('log')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
#ax.set_frame_on(False)

ax.legend()
ax.legend(loc='lower left')

fig.savefig("plots/exectime_train2.pdf", dpi=300)

for key in lens:
    print(key, 'nodes', np.sum(total_nodes[key])/len(total_nodes[key]), 'edges', np.sum(total_edges[key])/len(total_edges[key]))