
from id.id_service.magenid.idsapp.idsserver.views.home import *

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"

@ids.route('/clients')
@login_required
def get_clients():
    user = current_user()
    #clients = clientdao.getAllClientsByUserName(user.username)
    all_clients = clientdao.getAllClients()

    clients=[]
    for c in all_clients:

        if user.role!='admin':
           if c.user.username==user.username:
              clients.append(c)
        else:
            print('client_id=====',c.client_id)
            clients.append(c)

    return render_template('client-view.html',clients=clients,user=user,title='Available Clients')




@ids.route('/clients/add', methods=('GET', 'POST'))
@login_required
def add_client():
    user = current_user()

    if request.method == 'POST':
        dic = {}
        client_id = ""
        client_secret = ""
        client_name = request.form["client_name"]
        response_type = request.form["response_type"]
        redirect_uris = request.form["redirect_uris"]
        default_scopes = request.form.getlist('default_scopes')
        jwt_alg = request.form["jwt_alg"]
        dic=get_oauth_client_dic(client_name, redirect_uris, default_scopes, jwt_alg, client_id,
                             client_secret, response_type)
        client=clientdao.saveClient(user,dic)
        return redirect('/clients')
    else:
        return render_template('client-add.html',user=user,title='Add Client')




@ids.route('/clients/update/<client_id>', methods=('GET', 'POST'))
@login_required
def update_client(client_id):
    user = current_user()

    if request.method == 'POST':
        client=clientdao.saveClient(client_id,user,request)
        return redirect('/clients')
    else:
        client = clientdao.getClientByClientId(client_id)
        scopes=client.default_scopes
        #arr=scopes.split(',')
        print('scopes==scopes===',scopes)
        print('scopes=====',scopes[0])
        arrScope=scopes[0].split(',')
        client.default_scopes=arrScope
        return render_template('client-update.html',client=client,user=user,title='Edit Client')


@ids.route('/clients/view/<client_id>')
@login_required
def view_client(client_id):
    return redirect('/clients/update/'+client_id)

@ids.route('/clients/delete/<client_id>')
@login_required
def delete_client(client_id):
    user = current_user()
    print("client id==",client_id)
    client = clientdao.getClientByClientId(client_id)
    clientdao.deleteClient(client)

    return redirect('/clients')


