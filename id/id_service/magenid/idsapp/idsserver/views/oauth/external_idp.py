
from id.id_service.magenid.idsapp.idsserver.views.home import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

@ids.route('/idps')
@login_required
def idps():
    user = current_user()
    idps = extIdpDao.getAllIdps()
    for i in idps:
        print('=====namee======' + i.name)
    return render_template('ext-idp-list.html',idps=idps,user=user,title='Available IdPs')


@ids.route('/idps/add', methods=('GET', 'POST'))
@login_required
def add_idp():
    user = current_user()

    if request.method == 'POST':
        idp=extIdpDao.saveIdp(request)
        return redirect('/idps')
    else:
        return render_template('ext-idp-add.html',user=user,title='Add Client')



@ids.route('/idps/update/<name>', methods=('GET', 'POST'))
@login_required
def update_idp(name):
    user = current_user()

    if request.method == 'POST':
        idp=extIdpDao.updateIdp(name,request)
        return redirect('/clients')
    else:
        idp = extIdpDao.getIdpByName(name)
        return render_template('ext-idp-update.html',idp=idp,user=user,title='Edit idp')


@ids.route('/idps/view/<name>', methods=('GET', 'POST'))
@login_required
def view_idp(name):
    return redirect('/idps/update/'+name)

@ids.route('/idps/delete/<name>')
@login_required
def delete_idp(name):
    user = current_user()
    print("name==",name)
    idp = extIdpDao.getIdpByName(name)
    extIdpDao.deleteIdp(idp)

    return redirect('/idps')
