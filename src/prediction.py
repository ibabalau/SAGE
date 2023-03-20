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
    
## 2 sept 2020: Learning the model
def flexfringe(*args, **kwargs):
    '''Wrapper to call the flexfringe binary

    Keyword arguments:
    position 0 -- input file with trace samples
    kwargs -- list of key=value arguments to pass as command line arguments
    '''  
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
# cnt = 100

def create_train_test_traces(trace_file, use_random = False):
    traces = parse_file(trace_file)
    trainlen, testlen = round(len(traces)*0.8), round(len(traces)*0.2)
    if use_random:
        trainidx = random.sample(range(len(traces)), trainlen)
        testidx = [x for x in range(len(traces)) if x not in trainidx]
        train_data = [traces[i] for i in trainidx]
        test_data = [traces[i] for i in testidx]
    else:
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
        #multi.reverse()
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
            spdfa[str(node['id'])] = {'total_cnt': node['size'], 'symbol': '', 'fin': node['data']['total_final'], 'paths': node['data']['total_paths'], 'transitions': {k: int(v) for k,v in dict(node['data']['trans_counts']).items()}}
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
        #print('current node', node, 'trace', tr, 'prob list', pr_list)
        if tr == []:
            # end of trace reached, do stuff
            #print('end of trace reached')
            final_probs.append((pr_list, rev_spdfa[node]['symbol']))
            continue
        current_symb = tr[0]
        # check next transitions
        if current_symb == rev_spdfa[node]['symbol']:
            for item in rev_spdfa[node]['transitions']:
                # if firsy symbol, use ending prob, otheriwse normal prob
                if tr == trace:
                    q.put((item['target'], tr[1:], pr_list + [(node + '->' + item['target'], item['ending_prob'])]))
                else:
                    q.put((item['target'], tr[1:], pr_list + [(node + '->' + item['target'], item['prob'])]))
        elif rev_spdfa[node]['symbol'] == '':
            no_trans_cnt += 1
        else:
            no_symbol_cnt += 1
            # current_as = current_symb.split('|')[0]
            # actual_as = rev_spdfa[node]['symbol'].split('|')[0]
            # if current_as == actual_as:
            #     ind = np.argmax([item['prob'] for item in rev_spdfa[node]['transitions']])
            #     q.put((rev_spdfa[node]['transitions'][ind]['target'], tr[1:], pr_list + [(node + '->' + rev_spdfa[node]['transitions'][ind]['target'], rev_spdfa[node]['transitions'][ind]['prob'])]))
    return final_probs, 0 if no_symbol_cnt > no_trans_cnt else 1

def multiplyList(myList) :
    # Multiply elements one by one
    result = 1
    for y, x in myList:
        result = result * x
    return result

def test_prediction(rev_spdfa, test_data):
    no_path_cnt = 0
    no_next_action_cnt = 0
    fail_no_start_symb_cnt = 0
    fail_no_symbol_cnt = 0
    fail_no_transition_cnt = 0
    succ_cnt = 0
    tp_cnt = 0
    for test_trace in test_data:
        test_trace.reverse()
        true_action = test_trace[-1]
        test_trace = test_trace[:-1]
        print('---------------------------TESTING----------------------------')
        print('reversed input trace:', test_trace)
        if test_trace[0] not in symbol_to_state:
            fail_no_start_symb_cnt += 1
            continue
        start_nodes = list(symbol_to_state[test_trace[0]])
        print('starting nodes', start_nodes)
        prob_list, reason = find_probabilities(rev_spdfa, start_nodes, test_trace)
        if prob_list != []:
            probs_multiplied = [multiplyList(probs) for probs, _ in prob_list]
            mp_ind = np.argmax(probs_multiplied)
            print('true action is', true_action, 'predicted next action is', prob_list[mp_ind][1] if prob_list[mp_ind][1] != '' else 'none', 'with probability', probs_multiplied[mp_ind])
            print('node path in reversed spdfa', prob_list[mp_ind][0])
            if (prob_list[mp_ind][1] == ''):
                no_next_action_cnt += 1
                print('ROOT NODE')
            else:
                succ_cnt += 1
                if prob_list[mp_ind][1] == true_action:
                    tp_cnt += 1
        else:
            print('No valid paths found')
            if reason == 0:
                fail_no_symbol_cnt += 1
            else:
                fail_no_transition_cnt += 1
        print('--------------------------------------------------------------\n')

    test_tr_len = len(test_data)
    print('Total unique test traces', test_tr_len)
    print('Fail because starting symbol not found', fail_no_start_symb_cnt, fail_no_start_symb_cnt/test_tr_len)
    print('Fail because next symbol not found while following trace', fail_no_symbol_cnt, fail_no_symbol_cnt/test_tr_len)
    print('Fail because no more transition possible while following trace', fail_no_transition_cnt, fail_no_transition_cnt/test_tr_len)
    print('Successfully followed entire trace but no more transitions possible (root node)', no_next_action_cnt, no_next_action_cnt/test_tr_len)
    print('Successfully followed entire trace', succ_cnt, succ_cnt/test_tr_len, 'from which', tp_cnt, 'are true positives')

    return

dir_path = '/Users/ionbabalau/uni/thesis/SAGE'
flexfringe_path = '/Users/ionbabalau/uni/thesis/FlexFringe'
output_path = '/Users/ionbabalau/uni/thesis/SAGE/output_pred'
tr_file_name = dir_path + '/pred_traces/trace_all.txt'
USE_SINKS = True

### MAIN START ###
full_model_name, train_data, test_data = create_train_test_traces(tr_file_name, True)
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

test_prediction(rev_spdfa, test_data)