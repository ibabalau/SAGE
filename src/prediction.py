import time
import os, re
import os.path
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.style
import matplotlib as mpl

mpl.style.use('default')
import subprocess
from collections import defaultdict
from sklearn.model_selection import KFold
import json


class EvaluationMetrics:
    def __init__(self):
        self.top_3_accuracy_count = 0
        self.top_3_as_accuracy_count = 0
        self.severity_accuracy_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        self.severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        self.total_predictions = 0
        self.empty_count = 0
        self.total_execution_time = 0

    def update_metrics(self, true_labels, predicted_labels_list, execution_time):
        assert len(true_labels) == len(predicted_labels_list), "Mismatch in true and predicted labels count"

        self.total_predictions += len(true_labels)
        self.total_execution_time += execution_time

        for true_label, predicted_labels in zip(true_labels, predicted_labels_list):
            # Severity Accuracy
            true_label_stage = get_attack_stage(true_label)
            severity = self.get_label_severity(true_label_stage)
            self.severity_counts[severity] += 1

            if not predicted_labels:  # Check if prediction is empty
                self.empty_count += 1
                continue

            # Top-3 Accuracy
            if true_label in predicted_labels:
                self.top_3_accuracy_count += 1

            # Top-3 Attack Stage Accuracy
            predicted_stages = [get_attack_stage(label) for label in predicted_labels]
            if true_label_stage in predicted_stages:
                self.top_3_as_accuracy_count += 1
                self.severity_accuracy_counts[severity] += 1

    def get_label_severity(self, label):
        return as_to_sev[label]

    def calculate_metrics(self):
        top_3_accuracy = self.top_3_accuracy_count / self.total_predictions
        top_3_as_accuracy = self.top_3_as_accuracy_count / self.total_predictions
        severity_accuracy = {severity: self.severity_accuracy_counts[severity] / self.severity_counts[severity]
                             for severity in self.severity_counts if self.severity_counts[severity] > 0}
        average_execution_time = self.total_execution_time / self.total_predictions
        empty_percentage = self.empty_count / self.total_predictions

        # print('TOTAL', self.total_predictions)
        # total = 0
        # for sev in self.severity_counts:
        #     print(sev)
        #     print(self.severity_accuracy_counts[sev], self.severity_counts[sev])
        #     total += self.severity_counts[sev]
        # print('total', total)

        return {
            'Top 3 Accuracy': top_3_accuracy,
            'Top 3 Attack Stage Accuracy': top_3_as_accuracy,
            'Accuracy per Label Severity': severity_accuracy,
            'Average Execution Time': average_execution_time,
            'Empty Prediction Percentage': empty_percentage
        }


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

    if (len(kwargs) >= 1):
        command = []
        for key in kwargs:
            command += ['--' + key + '=' + kwargs[key]]

    result = subprocess.run([flexfringe_path + '/flexfringe', ] + command + [args[0]], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
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

    data = data.replace('\n', '').replace(',,', ',')  # .replace(', ,', ',')#.replace('    ', ' ')
    data = re.sub(r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', data)

    data = re.sub(',+', ',', data)
    machine = json.loads(data)

    dfa = defaultdict(lambda: defaultdict(str))

    for edge in machine['edges']:
        dfa[edge['source']][edge['name']] = (edge['target'], edge['appearances'])

    for entry in machine['nodes']:
        dfa[str(entry['id'])]['type'] = '0'
        dfa[str(entry['id'])]['isred'] = int(entry['isred'])

    return (dfa, machine)


def traverse(dfa, sinks, sequence, statelist=False):
    '''Wrapper to traverse a given model with a string

    Keyword arguments:
    dfa -- loaded model
    sequence -- space-separated string to accept/reject in dfa
    '''
    # print(dfa)
    # in_main_model = set()
    sev_sinks = set()
    state = '0'
    stlst = ['0']
    # print('This seq', sequence.split(' '))
    for event in sequence.split(' '):
        sym = event.split(':')[0]
        state = dfa[state][sym]

        if state != '':
            isred = dfa[state[0]]['isred']
        if state == '':
            try:
                state = sinks[stlst[-1]][sym][0]
                sev_sinks.add(state)
            except:
                state = '-1'
        else:
            try:
                # print('weird place')
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


def create_train_test_traces(train_data, test_data):  # trace_file, use_random = False, pdfa = False):
    print('Using', len(train_data), 'traces for training')
    print('Using', len(test_data), 'traces for testing')

    count_lines = 0
    count_cats = set()

    # create new train_traces file
    trace_file_name = 'train_traces.txt'
    trace_file_location = dir_path + '/pred_traces/'
    f = open(trace_file_location + trace_file_name, 'w')
    lines = []
    for i, trace in enumerate(train_data):
        count_lines += 1
        multi = trace
        for e in multi:
            count_cats.add(e)
        st = '1' + ' ' + str(len(multi)) + ' ' + ' '.join(multi) + '\n'
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()

    test_file_name = 'test_traces.txt'
    count_lines = 0
    count_cats = set()
    trace_file_location = dir_path + '/pred_traces/'
    f = open(trace_file_location + test_file_name, 'w')
    lines = []
    for i, trace in enumerate(test_data):
        count_lines += 1
        multi = trace
        for e in multi:
            count_cats.add(e)
        st = '1' + ' ' + str(len(multi)) + ' ' + ' '.join(multi) + '\n'
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()
    return trace_file_location + trace_file_name


def fix_syntax(fname, is_sink_file=False):
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
            spdfa[str(node['id'])] = {'total_cnt': node['size'], 'symbol': '', 'fin': node['data']['total_final'],
                                      'paths': node['data']['total_paths'],
                                      'transitions': {k: int(v) for k, v in dict(node['data']['trans_counts']).items()
                                                      if int(v) != 0}}
        else:
            spdfa[str(node['id'])] = {'total_cnt': node['size'], 'symbol': '', 'fin': node['data']['total_final'],
                                      'paths': 0, 'transitions': {}}

    for edge in data['edges']:
        spdfa[edge['source']]['transitions'][edge['name']] = {'dnode': edge['target'],
                                                              'count': spdfa[edge['source']]['transitions'][
                                                                  edge['name']]}
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
    rev_spdfa = {key: {'symbol': spdfa[key]['symbol'], 'transitions': []} for key in nodes}

    for edge in data['edges']:
        snode = edge['source']
        dnode = edge['target']
        symbol = edge['name']
        if spdfa[dnode]['fin'] != 0:
            ending_prob = (spdfa[snode]['transitions'][symbol]['count'] / spdfa[dnode]['total_cnt']) * spdfa[dnode][
                'fin'] / end_symb_cnt[symbol]
        else:
            ending_prob = 0
        prob = (spdfa[snode]['transitions'][symbol]['count'] / spdfa[dnode][
            'total_cnt'])  # * spdfa[snode]['transitions'][symbol]['count']/total_symb_cnt[symbol]
        rev_spdfa[dnode]['transitions'].append({'target': snode, 'prob': prob, 'ending_prob': ending_prob})
        symbol_to_state[symbol].add(dnode)
    return spdfa, rev_spdfa, symbol_to_state


def find_probabilities(rev_spdfa, start_nodes, trace):
    # q.put and q.get
    import queue
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
                q.put((rev_spdfa[node]['transitions'][ind]['target'], tr[1:], pr_list + [(node + '->' + rev_spdfa[node][
                    'transitions'][ind]['target'], rev_spdfa[node]['transitions'][ind]['prob'])]))
    return final_probs, 0 if no_symbol_cnt > no_trans_cnt else 1


from enum import Enum


class Strategy(Enum):
    BASELINE_RAND = 4
    BASELINE_PROB = 5
    FULL_MATCH = 1
    AS_MATCH = 2
    ALL = 3
    PDFA = 6


class Metric(Enum):
    ACCURACY = 1
    ACCURACY_AS = 2
    ACCURACY_AS_LOW = 3
    ACCURACY_AS_MED = 4
    ACCURACY_AS_HIGH = 5
    SKIP_CNT = 6
    EXEC_TIME = 7


def traverse_pnfa_bfs(rev_spdfa, start_nodes, trace, use_factor, strategy=Strategy.ALL):
    # q.put and q.get
    import queue
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
        # print('current node', node, 'trace', tr, 'prob list', pr_list)
        if not tr:
            # end of trace reached, do stuff
            # print('end of trace reached')
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
                        q.put((item['target'], tr[1:],
                               path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']],
                               prob * item[prob_key] * factor))
                else:
                    prob_to_redis.append(prob)
            elif strategy == Strategy.AS_MATCH:
                if current_symb == rev_spdfa[node]['symbol'] or current_as == actual_as:
                    for item in rev_spdfa[node]['transitions']:
                        q.put((item['target'], tr[1:],
                               path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']],
                               prob * item[prob_key] * factor))
                else:
                    prob_to_redis.append(prob)
            else:
                for item in rev_spdfa[node]['transitions']:
                    q.put((item['target'], tr[1:],
                           path + [node + '->' + item['target'] + '_' + rev_spdfa[node]['symbol']],
                           prob * item[prob_key] * factor))

    return final_probs, prob_to_redis


memo = {}
as_to_sev = {
    'None': 'None',
    'tarID': 'LOW',
    'surf': 'LOW',
    'hostD': 'LOW',
    'serD': 'LOW',
    'vulnD': 'LOW',
    'infoD': 'LOW',
    'uPrivEsc': 'MEDIUM',
    'rPrivEsc': 'MEDIUM',
    'netSniff': 'MEDIUM',
    'bfCred': 'MEDIUM',
    'acctManip': 'MEDIUM',
    'TOexp': 'MEDIUM',
    'PAexp': 'MEDIUM',
    'remoteexp': 'MEDIUM',
    'sPhish': 'MEDIUM',
    'servS': 'MEDIUM',
    'evasion': 'MEDIUM',
    'CnC': 'MEDIUM',
    'lateral': 'MEDIUM',
    'ACE': 'MEDIUM',
    'privEsc': 'MEDIUM',
    'endDOS': 'HIGH',
    'netDOS': 'HIGH',
    'serStop': 'HIGH',
    'resHJ': 'HIGH',
    'dDestruct': 'HIGH',
    'cWipe': 'HIGH',
    'dEncrypt': 'HIGH',
    'deface': 'HIGH',
    'dManip': 'HIGH',
    'exfil': 'HIGH',
    'delivery': 'HIGH',
}


def traverse_pnfa_dfs(rev_spdfa, state, trace, len_traces, use_factor, set_factor, strategy=Strategy.ALL):
    key = (state, tuple(trace))
    if key in memo:
        return memo[key]

    paths = []
    if not trace:
        return [([state], 1.0, rev_spdfa[state]['symbol'] if rev_spdfa[state]['symbol'] != '' else 'None')]

    symbol = trace[0]
    factor = 1
    prob_key = 'prob'
    current_as = symbol.split('|')[0]
    actual_as = rev_spdfa[state]['symbol'].split('|')[0]
    if rev_spdfa[state]['symbol'] == '':
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
        if rev_spdfa[state]['symbol'] == symbol:
            trans = rev_spdfa[state]['transitions']
        elif rev_spdfa[state]['symbol'] == symbol or current_as == actual_as:
            trans = rev_spdfa[state]['transitions']
        else:
            trans = [max(rev_spdfa[state]['transitions'], key=lambda x: x[prob_key])]
    next_states = [item['target'] for item in trans]
    next_probs = [item[prob_key] * factor for item in trans]

    for s, p in zip(next_states, next_probs):
        for path, prob, next_action in traverse_pnfa_dfs(rev_spdfa, s, trace[1:], len_traces, use_factor, set_factor,
                                                         strategy):
            paths.append(([state] + path, p * prob, next_action))

    memo[key] = paths
    return paths


def scale_and_normalize(prob_list, test_trace):
    final_paths = []
    prob_to_redistribute = []
    probs_to_scale = []
    for path in prob_list:
        # n symbols means n + 1 nodes in the path, so we remove paths that are incomplete
        if len(path[0]) != len(test_trace) + 1:
            prob_to_redistribute.append(path[1])
        else:
            final_paths.append(path)
            probs_to_scale.append(path[1])
    # if no possible paths are possible
    if len(final_paths) == 0:
        return []
    # normalization
    if prob_to_redistribute:
        probs_to_scale += prob_to_redistribute
    s = np.sum(probs_to_scale)
    if s != 0:
        normalized = [x / s for x in probs_to_scale]
    else:
        normalized = probs_to_scale
    new_probs = normalized[:len(final_paths)]

    # redistribution
    total_red = 0
    if prob_to_redistribute != []:
        prob_to_redistribute = normalized[-len(prob_to_redistribute):]
        probs_sum = np.sum(new_probs) + np.sum(prob_to_redistribute)
        # print('PROB SUM', probs_sum)
        if s != 0 and probs_sum < 0.99 or probs_sum > 1.01:
            print('ERR')
            exit()
        total_red = np.sum(prob_to_redistribute) / len(final_paths)
    return [(final_paths[i][0], normalized[i] + total_red, final_paths[i][2]) for i in range(len(final_paths))]


def top_3_accuracy(y_true, y_pred):
    for pred_action in y_pred:
        if pred_action == y_true:
            return y_true
    return 'None'


def top_3_accuracy_as(y_true, y_pred):
    for pred_action in y_pred:
        if get_attack_stage(pred_action) == get_attack_stage(y_true):
            return y_true
    return 'None'


def test_pred_sum(rev_spdfa, X_test, Y_test, strat, factor, symbol_to_state, results):
    memo.clear()
    total_stime = time.time()
    y_pred = []
    for test_trace, y_true in zip(X_test, Y_test):
        if test_trace[0] not in symbol_to_state:
            y_pred.append([])
            continue
        start_nodes = list(symbol_to_state[test_trace[0]])
        use_scaling = True
        prob_list = []
        for snode in start_nodes:
            prob_list += traverse_pnfa_dfs(rev_spdfa, snode, test_trace, len(test_trace), use_scaling, factor, strat)
        final_paths = scale_and_normalize(prob_list, test_trace)
        if prob_list == [] or final_paths == []:
            y_pred.append([])
            continue

        # finding next action
        next_actions = {}
        for path, prob, na in final_paths:
            if na in next_actions:
                next_actions[na] += prob
            else:
                next_actions[na] = prob
        sorted_pairs = sorted(next_actions.items(), key=lambda x: x[1], reverse=True)[:3]
        pred_actions = [x[0] for x in sorted_pairs]
        y_pred.append(pred_actions)
        print('finished with', len(test_trace))
    exec_time = time.time() - total_stime
    results[strat].update_metrics(Y_test, y_pred, exec_time)
    return


def get_attack_stage(symbol):
    if symbol == 'None':
        return symbol
    else:
        return symbol.split('|')[0]  # 😂


def find_path(pdfa, trace):
    node = '0'
    prob = 1
    for symbol in trace:
        if pdfa[node]['transitions'] == {}:
            return ([], 0)
        else:
            if symbol in pdfa[node]['transitions']:
                prob = prob * pdfa[node]['transitions'][symbol]['count'] / pdfa[node]['paths']
                node = pdfa[node]['transitions'][symbol]['dnode']
            else:
                trans = pdfa[node]['transitions']
                # get next node based on maximum probability
                next_node = sorted(trans.items(), key=lambda x: x[1]['count'], reverse=True)[0]
                symb = next_node[0]
                prob = prob * pdfa[node]['transitions'][symb]['count'] / pdfa[node]['paths']
                node = next_node[1]['dnode']

    if pdfa[node]['transitions'] == {}:
        return ([], 0)
    top3 = sorted(pdfa[node]['transitions'].items(), key=lambda x: x[1]['count'], reverse=True)[:3]
    top3 = [x[0] for x in top3]
    return (top3, prob)


def test_pdfa(pdfa, X_test, Y_test, results):
    # pdfa['node_id'] -> {'total_cnt', 'symbol', 'fin', 'paths', 'transitions' = {'symbol': {'dnode', 'count'}}}
    y_pred = []
    skip_cnt = 0
    start_time = time.time()
    for tt in X_test:
        preds, prob = find_path(pdfa, tt)
        y_pred.append(preds)
    exec_time = time.time() - start_time
    results[Strategy.PDFA].update_metrics(Y_test, y_pred, exec_time)


def test_baseline(train_data, X_test, Y_test, Y_test_as, uniq_symbs, results):
    probs = {symb: {next_symb: 0 for next_symb in uniq_symbs} for symb in uniq_symbs}
    for trace in train_data:
        for symbol, next_symbol in zip(trace, trace[1:]):
            probs[symbol][next_symbol] += 1
    # get top 3 predictions based on frequency
    next_actions = {symb: [x[0] for x in sorted(probs[symb].items(), key=lambda x: x[1], reverse=True)[:3]] for symb in
                    uniq_symbs}
    y_pred = []
    skip_cnt = 0
    stime = time.time()
    for trace in X_test:
        last_action = trace[-1]
        if last_action in next_actions:
            y_pred.append(next_actions[last_action])
        else:
            y_pred.append([])
    end_time = time.time() - stime
    results[Strategy.BASELINE_PROB].update_metrics(Y_test, y_pred, end_time)
    return


def test_baseline_rand(train_data, Y_test, results):
    alL_symbols = []
    for trace in train_data:
        for symb in trace:
            alL_symbols.append(symb)
    unique_classes, counts = np.unique(alL_symbols, return_counts=True)
    probabilities = counts / counts.sum()
    np.random.seed(42)
    stime = time.time()
    random_predictions = [list(np.random.choice(unique_classes, size=3, p=probabilities, )) for y in Y_test]
    end_time = time.time() - stime
    results[Strategy.BASELINE_RAND].update_metrics(Y_test, random_predictions, end_time)


def bar_plot():
    # Create subplots
    fig, ax = plt.subplots()  # 1 row, 3 columns

    labels = ['Low', 'Medium', 'High']
    # ax.bar(labels, as_count.values(), edgecolor='black')

    ax.set_title('Severity distribution of last symnols in CPTC-2018 traces', fontsize=13, fontfamily='serif')
    ax.set_xlabel('Severity', fontsize=12, fontfamily='serif')
    ax.set_ylabel('Count', fontsize=12, fontfamily='serif')

    # Display the plot
    fig.savefig('plots/severity_distrib.pdf', dpi=300)


def line_plot(x, values, keys):
    fig, ax = plt.subplots()

    # Plot the values
    x_axis = x
    for key, val in zip(keys, values):
        y_values = val
        # y_values = [np.sum(sublist)/len(sublist) for k,sublist in val.items()]
        # x_axis = [k for k, _ in val.items()]
        ax.plot(x_axis, y_values, label=key, linestyle='-', marker='o')

    x_ticks = [1, 5] + [i for i in range(10, 100, 5)] + [x[-1]]
    # Set the title and axis labels
    ax.set_title('Accuracy for different multiplication factors', fontsize=13, fontfamily='serif')
    ax.set_xlabel('Factor', fontsize=12, fontfamily='serif')
    ax.set_ylabel('Accuracy', fontsize=12, fontfamily='serif')
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(str(i) for i in x_ticks)
    # ax.set_yscale('log')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    # ax.set_frame_on(False)

    ax.legend()
    ax.legend(loc='lower left')

    fig.savefig("plots/final_plots/factors.pdf", dpi=300)


def is_subsequence(small, large):
    """
    Check if 'small' list is a subsequence of 'large' list.
    """
    iter_large = iter(large)
    return all(item in iter_large for item in small)


def filter_unique_samples(dataset):
    """
    Filter the dataset to include only samples that are not a subsequence of any other sample.
    """
    unique_samples = []
    for i, sample in enumerate(dataset):
        # Check if 'sample' is a subsequence of any other sample
        if not any(is_subsequence(sample, other) for j, other in enumerate(dataset) if i != j):
            unique_samples.append(sample)
    return unique_samples


dir_path = '/Users/ionbabalau/uni/thesis/SAGE'
flexfringe_path = '/Users/ionbabalau/uni/thesis/SAGE/FlexFringe'
output_path = '/Users/ionbabalau/uni/thesis/SAGE/output_pred'
tr_file_name = dir_path + '/pred_traces/trace_all.txt'
USE_SINKS = True


### MAIN START ###
def run_experiments():
    results = {strategy: EvaluationMetrics() for strategy in Strategy}
    cnt = 15
    K = 13
    max_len = 6
    lens = [i for i in range(300, 501, 25)]
    total_nodes = []
    total_edges = []

    traces = parse_file(tr_file_name)
    as_traces = []
    for trace in traces:
        trace.reverse()

    # uncomment for unseen traces exp
    # unique_trace = [list(y) for y in set([tuple(x) for x in traces])]
    # unique_trace = filter_unique_samples(unique_trace)
    unique_trace = traces
    factor = 75
    kf = KFold(n_splits=K, shuffle=True, random_state=42)
    for train_index, test_index in kf.split(unique_trace):
        test_data = [unique_trace[i] for i in test_index]
        # train_data = []
        # for tr in traces:
        #     if tr not in test_data:
        #         train_data.append(tr)
        test_data = [trace[:max_len] for trace in test_data]
        train_data = [unique_trace[i] for i in train_index]
        # now test with pdfa
        full_model_name = create_train_test_traces(train_data, test_data)
        unique_sym = set([item for sublist in train_data for item in sublist])
        test_data = sorted(test_data, key=len)
        X_test = [trace[:-1] for trace in test_data]
        Y_test = [trace[-1] for trace in test_data]
        Y_test_as = [get_attack_stage(symb) for symb in Y_test]

        if USE_SINKS:
            path_to_ini = flexfringe_path + '/ini/spdfa-config-sinks.ini'
        else:
            path_to_ini = flexfringe_path + '/ini/spdfa-config.ini'

        print('------ Learning SPDFA ---------')
        # Learn S-PDFA
        flexfringe(full_model_name, ini=path_to_ini)

        # os.system('dot -Tpng ' + full_model_name + '.ff.final.dot -o ' + output_path + '/main_model.png')
        fix_syntax(full_model_name)

        print('------ Loading and traversing SPDFA ---------')
        model, data = loadmodel(full_model_name + '.ff.final.json')
        os.system('cp ' + full_model_name + '.ff.final.json ' + output_path + '/main.json')
        os.system('cp ' + full_model_name + '.ff.finalsinks.json ' + output_path + '/sinks.json')

        spdfa, rev_spdfa, symbol_to_state = create_structs(data, unique_sym, train_data)

        test_pdfa(spdfa, X_test, Y_test, results)

        for trace in train_data:
            trace.reverse()
        full_model_name = create_train_test_traces(train_data, test_data)
        unique_sym = set([item for sublist in train_data for item in sublist])

        if USE_SINKS:
            path_to_ini = flexfringe_path + '/ini/spdfa-config-sinks.ini'
        else:
            path_to_ini = flexfringe_path + '/ini/spdfa-config.ini'

        print('------ Learning SPDFA ---------')
        # Learn S-PDFA
        flexfringe(full_model_name, ini=path_to_ini)

        # os.system('dot -Tpng ' + full_model_name + '.ff.final.dot -o ' + output_path + '/main_model.png')

        fix_syntax(full_model_name)

        print('------ Loading and traversing SPDFA ---------')
        model, data = loadmodel(full_model_name + '.ff.final.json')
        os.system('cp ' + full_model_name + '.ff.final.json ' + output_path + '/main.json')
        os.system('cp ' + full_model_name + '.ff.finalsinks.json ' + output_path + '/sinks.json')

        spdfa, rev_spdfa, symbol_to_state = create_structs(data, unique_sym, train_data)

        test_baseline_rand(train_data, Y_test, results)
        test_baseline(train_data, X_test, Y_test, Y_test_as, unique_sym, results)
        print('----------FULL MATCH---------------')
        test_pred_sum(rev_spdfa, X_test, Y_test, Strategy.FULL_MATCH, factor, symbol_to_state, results)
        print('----------AS MATCH----------------------')
        test_pred_sum(rev_spdfa, X_test, Y_test, Strategy.AS_MATCH, factor, symbol_to_state, results)
        print('----------ANY SYMBOL-------------------------')
        test_pred_sum(rev_spdfa, X_test, Y_test, Strategy.ALL, factor, symbol_to_state, results)
        for trace in train_data:
            trace.reverse()

    for strat in Strategy:
        print(strat)
        print(results[strat].calculate_metrics())


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
    # print('Predicted', na, 'with prob', prob, 'for input trace', input)
    return na, prob

run_experiments()