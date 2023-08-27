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
from sklearn.metrics import accuracy_score
import json

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


def create_structs(data, unique_sym, train_data):
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
    'None': 'None',
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

def traverse_pnfa_dfs(rev_spdfa, state, trace, len_traces, use_factor, set_factor, strategy = Strategy.ALL):
    key = (state, tuple(trace))
    #print('KEY', key)
    if key in memo:
        return memo[key]
    
    paths = []
    if not trace:
        #print('trace finished, returning')
        return [([state], 1.0, rev_spdfa[state]['symbol'] if rev_spdfa[state]['symbol'] != '' else 'None')]

    symbol = trace[0]
    factor = 1
    prob_key = 'prob'
    current_as = symbol.split('|')[0]
    actual_as = rev_spdfa[state]['symbol'].split('|')[0]
    if rev_spdfa[state]['symbol'] == '':
        #print('root node reached, returning')
        return [([state], 1.0, 'None')]
    else:
        if use_factor:
            if symbol == rev_spdfa[state]['symbol']:
                factor = set_factor * 2
            elif current_as == actual_as:
                factor = set_factor
        # first symbol -> use ending prob instead
        if len(trace) == len_traces:
            prob_key = 'ending_prob'

    #print('current symbol', symbol)
    trans = []
    if strategy == Strategy.FULL_MATCH:
        if rev_spdfa[state]['symbol'] == symbol:
            trans = rev_spdfa[state]['transitions']
        else:
            return [([state], 1.0, rev_spdfa[state]['symbol'] if rev_spdfa[state]['symbol'] != '' else 'None')]
    elif strategy == Strategy.AS_MATCH:
        if rev_spdfa[state]['symbol'] == symbol or current_as == actual_as:
            trans = rev_spdfa[state]['transitions']
        else:
            return [([state], 1.0, rev_spdfa[state]['symbol'] if rev_spdfa[state]['symbol'] != '' else 'None')]
    else:
        trans = rev_spdfa[state]['transitions']
    next_states = [item['target'] for item in trans]
    next_probs = [item[prob_key] * factor for item in trans]

    for s, p in zip(next_states, next_probs):
        for path, prob, next_action in traverse_pnfa_dfs(rev_spdfa, s, trace[1:], len_traces, use_factor, set_factor, strategy):
            paths.append(([state] + path, p * prob, next_action))
    
    memo[key] = paths
    #print('adding to memo and returning, key', key)
    return paths

def test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, strat, factor):
    global result_dict
    global conf_severities
    global test_set_preds
    global true_preds
    global accuracy_per_sev
    memo.clear()
    skip_cnt = 0
    total_stime = time.time()
    accuracy_per_as = {'LOW':0, 'MEDIUM':0, 'HIGH':0}
    as_count = {'LOW':0, 'MEDIUM':0, 'HIGH':0}
    y_pred = []
    for test_trace, y_true in zip(X_test, Y_test):
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
            prob_list += traverse_pnfa_dfs(rev_spdfa, snode, test_trace, len(test_trace), use_scaling, factor, strat)
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
            if len(path[0]) != len(test_trace) + 1:
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
        pred_action = sorted_pairs[0][0]
        y_pred.append(pred_action)
        if strat == Strategy.ALL:
            conf_severities[as_to_sev[get_attack_stage(y_true)]][as_to_sev[get_attack_stage(pred_action)]] += 1
            if y_true == pred_action:
                accuracy_per_as[as_to_sev[get_attack_stage(y_true)]] += 1
            as_count[as_to_sev[get_attack_stage(y_true)]] += 1            
        if strat == Strategy.ALL:
            test_set_preds.append(as_to_sev[get_attack_stage(pred_action)])
            true_preds.append(as_to_sev[get_attack_stage(y_true)])
        print('finished with', len(test_trace))
        #print('--------------------------------------------------------------\n')    

    for key in accuracy_per_as:
        if as_count[key] != 0:
            accuracy_per_sev[key].append(accuracy_per_as[key]/as_count[key])
    print(accuracy_per_as)
    print(accuracy_per_sev)
    y_pred_as = [get_attack_stage(symb) for symb in y_pred]
    exec_time = time.time() - total_stime
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
    prob = 1
    for symbol in trace:
        if pdfa[node]['transitions'] == {}:
            return ('None', 0), 1
        else:
            if symbol in pdfa[node]['transitions']:
                prob = prob * pdfa[node]['transitions'][symbol]['count']/pdfa[node]['paths']
                node = pdfa[node]['transitions'][symbol]['dnode']
            else:
                trans = pdfa[node]['transitions']
                # get next node based on maximum probability
                next_node = sorted(trans.items(), key=lambda x: x[1]['count'], reverse=True)[0]
                symb = next_node[0]
                prob = prob * pdfa[node]['transitions'][symb]['count']/pdfa[node]['paths']
                node = next_node[1]['dnode']

    if pdfa[node]['transitions'] == {}:
        return ('None', 0), 0
    return (sorted(pdfa[node]['transitions'].items(), key=lambda x: x[1]['count'], reverse=True)[0][0], prob), 0

def test_pdfa(pdfa, X_test, Y_test, Y_test_as):
    global result_pdfa
    # pdfa['node_id'] -> {'total_cnt', 'symbol', 'fin', 'paths', 'transitions' = {'symbol': {'dnode', 'count'}}}
    y_pred = []
    skip_cnt = 0
    start_time = time.time()
    for tt in X_test:
        (na, prob), skip = find_path(pdfa, tt)
        y_pred.append(na)    
        skip_cnt += skip  
        # if get_attack_stage(pred[0]) == get_attack_stage(true_action):
        #     accuracy_per_as[as_to_sev[get_attack_stage(true_action)]] += 1
        # as_count[as_to_sev[get_attack_stage(true_action)]] += 1
    exec_time = time.time() - start_time
    y_pred_as = [get_attack_stage(symb) for symb in y_pred]
    result_pdfa[Metric.ACCURACY].append(accuracy_score(Y_test, y_pred))
    result_pdfa[Metric.ACCURACY_AS].append(accuracy_score(Y_test_as, y_pred_as))
    result_pdfa[Metric.SKIP_CNT].append(skip_cnt/len(X_test))
    result_pdfa[Metric.EXEC_TIME].append(exec_time)
    return 
    

def test_baseline(train_data, X_test, Y_test, Y_test_as, uniq_symbs):
    global result_dict
    probs = {symb: {next_symb: 0 for next_symb in uniq_symbs} for symb in uniq_symbs}
    for trace in train_data:
        for symbol, next_symbol in zip(trace, trace[1:]):
            probs[symbol][next_symbol] += 1
    next_actions = {symb: sorted(probs[symb].items(), key=lambda x: x[1], reverse=True)[:1][0][0] for symb in uniq_symbs}
    y_pred = []
    skip_cnt = 0
    stime = time.time()
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
    result_dict[Strategy.BASELINE_PROB][Metric.EXEC_TIME].append(time.time() - stime)
    return

def test_baseline_rand(Y_test, Y_test_as):
    global result_dict
    last_symbols = set(Y_test)
    last_symbols_as = set(Y_test_as)
    result_dict[Strategy.BASELINE_RAND][Metric.ACCURACY].append(1/len(last_symbols))
    result_dict[Strategy.BASELINE_RAND][Metric.ACCURACY_AS].append(1/len(last_symbols_as))


def bar_plot():
    # Create subplots
    fig, ax = plt.subplots()  # 1 row, 3 columns

    labels = ['Low', 'Medium', 'High']
    ax.bar(labels, as_count.values(), edgecolor='black')

    ax.set_title('Severity distribution of last symnols in CPTC-2018 traces', fontsize=13, fontfamily='serif')
    ax.set_xlabel('Severity',  fontsize=12, fontfamily='serif')
    ax.set_ylabel('Count',  fontsize=12, fontfamily='serif')


    # Display the plot
    fig.savefig('plots/severity_distrib.pdf', dpi=300)

def line_plot(x, values, keys):
    fig, ax = plt.subplots()

    # Plot the values
    x_axis = x
    for key, val in zip(keys, values):
        y_values = val
        #y_values = [np.sum(sublist)/len(sublist) for k,sublist in val.items()]
        #x_axis = [k for k, _ in val.items()]
        ax.plot(x_axis, y_values, label=key, linestyle='-', marker='o')

    x_ticks = [1, 5] + [i for i in range (10, 100, 5)] + [x[-1]]
    # Set the title and axis labels
    ax.set_title('Accuracy for different multiplication factors', fontsize=13, fontfamily='serif')
    ax.set_xlabel('Factor', fontsize=12, fontfamily='serif')
    ax.set_ylabel('Accuracy', fontsize=12, fontfamily='serif')
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(str(i) for i in x_ticks)
    #ax.set_yscale('log')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    #ax.set_frame_on(False)

    ax.legend()
    ax.legend(loc='lower left')

    fig.savefig("plots/final_plots/factors.pdf", dpi=300)

dir_path = '/Users/ionbabalau/uni/thesis/SAGE'
flexfringe_path = '/Users/ionbabalau/uni/thesis/FlexFringe'
output_path = '/Users/ionbabalau/uni/thesis/SAGE/output_pred'
tr_file_name = dir_path + '/pred_traces/trace_all.txt'
USE_SINKS = True
result_dict = {strategy: {key:[] for key in Metric} for strategy in Strategy}

### MAIN START ###

# result_pdfa = {key:[] for key in Metric}
# conf_severities = {'LOW':{'LOW':0, 'MEDIUM':0, 'HIGH':0, 'None': 0}, 'MEDIUM':{'LOW':0, 'MEDIUM':0, 'HIGH':0, 'None': 0}, 'HIGH':{'LOW':0, 'MEDIUM':0, 'HIGH':0, 'None': 0}}
# accuracy_per_sev = {'LOW':[], 'MEDIUM':[], 'HIGH':[]}
# test_set_preds = []
# true_preds = []

# cnt = 15
# K = 13
# max_len = 6
# lens = [i for i in range(300, 501, 25)]
# total_nodes = []
# total_edges = []

# traces = parse_file(tr_file_name)
# as_traces = []
# for trace in traces:
#     #trace = [get_attack_stage(symb) for symb in trace]
#     trace.reverse()
#     #as_traces.append(trace)
# #traces = as_traces

# accuracy_per_as = {'LOW':0, 'MEDIUM':0, 'HIGH':0}
# as_count = {'LOW':0, 'MEDIUM':0, 'HIGH':0}
# for trace in traces:
#     last = trace[-1]
#     as_count[as_to_sev[get_attack_stage(last)]] += 1
# print(as_count)

# k_accuracies = {k:[] for k in Strategy}

# unique_trace = [list(y) for y in set([tuple(x) for x in traces])]
# unique_trace = [x for x in unique_trace  if len(x) <= max_len]
# #factors = [1, 2, 5, 8] + [i for i in range (10, 100, 5)]
# factor = 75
# #accuracies_fact_dict = {strategy: {key: [] for key in factors} for strategy in [Strategy.AS_MATCH, Strategy.ALL]}
# #result_dict = {strategy: {key:[] for key in Metric} for strategy in Strategy}
# #for cnt in range(5, 16):
# kf = KFold(n_splits=K, shuffle=True)
# for train_index, test_index in kf.split(unique_trace):
#     #for factor in factors:
#     test_data = [unique_trace[i] for i in test_index]
#     print(test_data)
#     train_data = []
#     for trace in traces:
#         if trace not in test_data:
#             train_data.append(trace)
#     # train_data = train_data[:500]
#     # now test with pdfa
#     full_model_name = create_train_test_traces(train_data, test_data)
#     unique_sym = set([item for sublist in train_data for item in sublist])
#     test_data = sorted(test_data, key=len)
#     X_test = [trace[:-1] for trace in test_data]
#     Y_test = [trace[-1] for trace in test_data]
#     Y_test_as = [get_attack_stage(symb) for symb in Y_test]

#     if USE_SINKS:
#         path_to_ini = flexfringe_path + '/ini/spdfa-config-sinks.ini'
#     else:
#         path_to_ini = flexfringe_path + '/ini/spdfa-config.ini'

#     print('------ Learning SPDFA ---------')
#     # Learn S-PDFA
#     flexfringe(full_model_name, ini=path_to_ini)

#     #os.system('dot -Tpng ' + full_model_name + '.ff.final.dot -o ' + output_path + '/main_model.png')
#     fix_syntax(full_model_name)

#     print('------ Loading and traversing SPDFA ---------')
#     model, data = loadmodel(full_model_name + '.ff.final.json')
#     os.system('cp ' + full_model_name + '.ff.final.json ' + output_path + '/main.json')
#     os.system('cp ' + full_model_name + '.ff.finalsinks.json '+ output_path + '/sinks.json')

#     spdfa, rev_spdfa, symbol_to_state = create_structs(data, unique_sym, train_data)

#     test_pdfa(spdfa, X_test, Y_test, Y_test_as)


#     for trace in train_data:
#         trace.reverse()
#     full_model_name = create_train_test_traces(train_data, test_data)
#     unique_sym = set([item for sublist in train_data for item in sublist])

#     if USE_SINKS:
#         path_to_ini = flexfringe_path + '/ini/spdfa-config-sinks.ini'
#     else:
#         path_to_ini = flexfringe_path + '/ini/spdfa-config.ini'

#     print('------ Learning SPDFA ---------')
#     # Learn S-PDFA
#     flexfringe(full_model_name, ini=path_to_ini)

#     #os.system('dot -Tpng ' + full_model_name + '.ff.final.dot -o ' + output_path + '/main_model.png')

#     fix_syntax(full_model_name)

#     print('------ Loading and traversing SPDFA ---------')
#     model, data = loadmodel(full_model_name + '.ff.final.json')
#     os.system('cp ' + full_model_name + '.ff.final.json ' + output_path + '/main.json')
#     os.system('cp ' + full_model_name + '.ff.finalsinks.json '+ output_path + '/sinks.json')

#     spdfa, rev_spdfa, symbol_to_state = create_structs(data, unique_sym, train_data)

#     test_baseline_rand(Y_test, Y_test_as)
#     test_baseline(train_data, X_test, Y_test, Y_test_as, unique_sym)
#     test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, Strategy.FULL_MATCH, factor)
#     print('------------------------------------------')
#     test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, Strategy.AS_MATCH, factor)
#     print('------------------------------------------')
#     test_pred_sum(spdfa, rev_spdfa, X_test, Y_test, Y_test_as, Strategy.ALL, factor)
#     for trace in train_data:
#         trace.reverse()
#     #accuracies_fact_dict[Strategy.AS_MATCH][factor].append(result_dict[Strategy.AS_MATCH][Metric.ACCURACY][0])
#     #accuracies_fact_dict[Strategy.ALL][factor].append(result_dict[Strategy.ALL][Metric.ACCURACY][0])
# # for k in Strategy:
#     #     k_accuracies[k].append(sum(result_dict[k][Metric.ACCURACY])/len(result_dict[k][Metric.ACCURACY]))
#     #result_dict = {strategy: {key:[] for key in Metric} for strategy in Strategy}
# #print(accuracies_fact_dict)
# #as_match = [sum(accuracies_fact_dict[Strategy.AS_MATCH][factor])/len(accuracies_fact_dict[Strategy.AS_MATCH][factor]) for factor in factors]
# #full_match = [sum(accuracies_fact_dict[Strategy.ALL][factor])/len(accuracies_fact_dict[Strategy.ALL][factor]) for factor in factors]

# #line_plot(factors, [as_match, full_match], [Strategy.AS_MATCH, Strategy.ALL])


# print('-----------')
# for strat in Strategy:
#     print(strat)
#     for metric in Metric:
#         if len(result_dict[strat][metric]) != 0:
#             print(metric, sum(result_dict[strat][metric])/len(result_dict[strat][metric]))
#     print()

# print()
# print('Strategy.PDFA')
# for metric in Metric:
#     if len(result_pdfa[metric]) != 0:
#         print(metric, sum(result_pdfa[metric])/len(result_pdfa[metric]))
# print()

#     # print('nodes', np.sum(total_nodes)/len(total_nodes), 'edges', np.sum(total_edges)/len(total_edges))

# for k,v in accuracy_per_sev.items():
#     print(k, np.sum(v)/len(v))

#     # from sklearn.metrics import confusion_matrix
#     # confusion_matrix_result = confusion_matrix(true_preds, test_set_preds, labels=['LOW', 'MEDIUM', 'HIGH', 'None'])

#     # print(np.unique(true_preds))
#     # print("Confusion Matrix:")
#     # print(confusion_matrix_result)

# #def predict_next_action(input):

def train_pdfa():
    tr_file_name = '/Users/ionbabalau/uni/thesis/SAGE/pred_traces/traces_team125_pdfa.txt'
    train_data = parse_file(tr_file_name)
    unique_sym = set([item for sublist in train_data for item in sublist])
    path_to_ini = flexfringe_path + '/ini/spdfa-config-sinks.ini'

    print('------ Learning SPDFA ---------')
    # Learn S-PDFA
    flexfringe(tr_file_name, ini=path_to_ini)
    fix_syntax(tr_file_name)

    print('------ Loading and traversing SPDFA ---------')
    model, data = loadmodel(tr_file_name + '.ff.final.json')
    spdfa, rev_spdfa, symbol_to_state = create_structs(data, unique_sym, train_data)
    with open('/Users/ionbabalau/uni/thesis/SAGE/prediction_pdfa.json', 'w') as fp:
        json.dump(spdfa, fp)

def pdfa_predict_next_action(input):
    with open('/Users/ionbabalau/uni/thesis/SAGE/prediction_pdfa.json', 'r') as fp:
        pdfa = json.load(fp)
    (na, prob), skip = find_path(pdfa, input)
    #print('Predicted', na, 'with prob', prob, 'for input trace', input)
    return na, prob

#testkfold()
