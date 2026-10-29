import pytest
import analysis
from intelligence import vt_points
from reports import actions

@pytest.mark.parametrize('score,level',[(0,'Low risk'),(18,'Low risk'),(19,'Low risk'),(20,'Low risk'),(30,'Low risk'),(31,'Suspicious'),(69,'Suspicious'),(70,'Dangerous'),(100,'Dangerous')])
def test_three_severity_boundaries(score,level):
    row=analysis.record('file','hash-only')
    row['providers']=[{'state':'completed','hasEvidence':True,'reputationPoints':min(score,90)}]
    if score==100:
        analysis.finding(row,'macro','macro component')
    value=analysis.finish(row)
    assert value['risk']['level']==level
    assert value['risk']['score']==score
    band=actions(value)['band']
    assert band==('high' if score>=70 else 'review' if score>30 else 'limited')

@pytest.mark.parametrize('stats,expected',[
 ({'suspicious':2,'undetected':68},18),
 ({'suspicious':2,'undetected':8},19),
 ({'malicious':1,'undetected':69},20),
 ({'malicious':50,'undetected':20},80),
 ({'undetected':70},0),
])
def test_specific_integer_scores(stats,expected):
    assert vt_points(stats)==expected
    assert isinstance(vt_points(stats),int)
    assert vt_points(stats)==vt_points(stats) # same evidence gives the same score


def test_unknown_remains_unknown():
    row=analysis.record('file','unknown.bin')
    assert analysis.finish(row)['risk']['score'] is None
    assert actions(row)['band']=='unknown'
