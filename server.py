import flask,random,string
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import hashlib,os
app = Flask(__name__)

CORS(app, origins = "http://127.0.0.1:7070")
ischecked = False
app.secret_key = '468c84aeb4c135be4b65a7961153'
my_custom_string = "-+*(#@!)$%~?"
data_ready_to_modify = {}
newest_search_str=""
exceptstr=["&gt","&lt","&amp","&quot","&apos",]

def GetCurrentPath():
    CurrentPath = os.path.abspath(__file__)
    str = CurrentPath.split('\\')
    str.pop()
    str = ('\\'+'\\').join(str)+('\\'+'\\')
    return str

def GetSHA256(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def CheckLogin():
    if session.get('havedLogin') == 2:
        return True
    else:
        return False
def randomPasswordGenerator(length,mode):
    if mode == 0:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    elif mode == 1:
        return ''.join(random.choices(string.ascii_letters + my_custom_string + string.digits, k=length))
    

def aes256_encrypt(plain_text, key):
    fixed_iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv=fixed_iv)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    ct = fixed_iv + ct_bytes  
    return ct.hex()

def aes256_decrypt(cipher_text, key):
    fixed_iv = b'\x00' * 16
    ct_bytes = bytes.fromhex(cipher_text)[16:]  
    cipher = AES.new(key, AES.MODE_CBC, iv=fixed_iv)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode('utf-8')

def sha256_to_256_bytes(plain_text):
    sha256 = bytes.fromhex(plain_text)
    return sha256

def hash_string_sha3_256(input_string):
    sha3_256_hash = hashlib.sha3_256()
    sha3_256_hash.update(input_string.encode('utf-8'))
    hex_dig = sha3_256_hash.hexdigest()
    return hex_dig

def search_text(target_text, key):
    if key.lower() in target_text.lower():
        return True
    else:
        return False


@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    if request.method == 'POST':
        data = request.get_json()
        account = data.get('account')
        password = data.get('password')
        sourcePassword = password
        # 在这里进行用户名和密码的验证
        password = GetSHA256(password+"salt")
        account = GetSHA256(account)
        with open(GetCurrentPath()+"data\\accountdatabase.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line == account + ' ' + password:
                    session['account'] = account
                    session['password'] = sourcePassword
                    session['havedLogin'] = 2 #####!!!!
                    return jsonify({'code': 200, 'message': '登录成功'})
        return jsonify({'code': 401, 'message': '账号或密码错误'})
@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])   
def register_post():
    if request.method == 'POST':
        data = request.get_json()
        account = data.get('account')
        password = data.get('password')
        # print(account,password)
        # 在这里进行用户名和密码的验证

        if (account) and (password):
            password = GetSHA256(password+"salt")
            account = GetSHA256(account)
            os.makedirs(GetCurrentPath()+'data', exist_ok=True)
            for line in open(GetCurrentPath()+"data\\accountdatabase.txt", "r"):
                if line.strip().split(' ')[0] == account:
                    return jsonify({'code': 401, 'message': '账号已存在'})
            with open(GetCurrentPath()+"data\\accountdatabase.txt", "a") as f:
                f.write(account + " " + password + "\n")
            with open(GetCurrentPath()+'data\\'+ account +".txt", 'w', encoding='utf-8') as file:
                pass
            return jsonify({'code': 200, 'message': '注册成功'})
        else:
            return jsonify({'code': 401, 'message': '账号或密码不能为空'})
        
@app.route("/main")
def main():
    #print(session.get('havedLogin'))
    if CheckLogin():
        return render_template('main.html')
    else:
        flash('请先登录', 'error')
        return redirect(url_for('login'))

@app.route("/main/passwordGenerator")
def passwordGenerator():
    #print(session.get('havedLogin'))
    if CheckLogin():
        return render_template('passwordGenerator.html')
    else:
        flash('请先登录', 'error')
        return redirect(url_for('login'))

@app.route("/main/passwordGenerator", methods=['POST'])
def passwordGenerator_post():
    global ischecked
    if request.method == 'POST':
        data = request.get_json()
        if not CheckLogin():
            return jsonify({'code': 401, 'message': '请先登录'})
        if "ischecked" in data:
            ischecked = data.get('ischecked')
            return jsonify({'code': 200, 'message': '传输成功'})
        if data.get('ispasswordGenerator1btnPressed'):
            passwordLen = 256
            flagHaveotherletter = False
            length = data.get('passwordlen')
            print(length)
            for i in range(len(length)):
                if length[i] not in '0123456789':
                    flagHaveotherletter = True
            if flagHaveotherletter:
                return jsonify({'code': 402, 'message': '密码长度只能为数字'})
            if len(length)!=0 and int(length) > 512:
                return jsonify({'code': 403, 'message': '密码长度不能超过512位'})
            if len(length) != 0:
                passwordLen = int(length)
            return jsonify({'code': 200, 'message': '传输成功','password': randomPasswordGenerator(passwordLen,ischecked)})
        
@app.route("/main/logout")
def logout():
    session.pop('account', None)
    session.pop('password', None)
    session.pop('havedLogin', None)
    return redirect(url_for('login'))
@app.route("/main/passwordSave")
def passwordSave():
    if CheckLogin():
        return render_template('passwordSave.html')
    else:
        flash('请先登录', 'error')
        return redirect(url_for('login'))

@app.route("/main/passwordGetor",methods=['POST'])
def passwordGetor():
    if request.method == 'POST':
        data = request.get_json()
        if not CheckLogin():
            return jsonify({'code': 401, 'message': '请先登录'})
        password = data.get('password')
        commitDataInputText = data.get('commitDataInputText')
        # print(password,commitDataInputText)
        if '<' in password or '>' in password or '<' in commitDataInputText or '>' in commitDataInputText:
            return jsonify({'code': 201, 'message': '密码或备注不能包含<或>'})
        for i in exceptstr:
            if i in password or i in commitDataInputText:
                return jsonify({'code': 202, 'message': '密码或备注不能包含'+i})
        # print(password,commitDataInputText)
        with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "a") as f:
            f.write(aes256_encrypt(password,sha256_to_256_bytes(hash_string_sha3_256(session['password']))) + " " + aes256_encrypt(commitDataInputText,sha256_to_256_bytes(hash_string_sha3_256(session['password']))) + "\n")
        return jsonify({'code': 200, 'message': '传输成功'})
    
@app.route("/main/passwordSearch")
def passwordSearch():
    if CheckLogin():
        return render_template('passwordSearch.html')
    else:
        flash('请先登录', 'error')
        return redirect(url_for('login'))

@app.route("/main/passwordSearch",methods=['POST'])
def passwordSearch_post():
    global newest_search_str
    if request.method == 'POST':
        data = request.get_json()
        commitDataInputText = data.get('commitDataInputText')
        if not CheckLogin():
            return jsonify({'code': 401, 'message': '请先登录'})
        if '<' in commitDataInputText or '>' in commitDataInputText:
            return jsonify({'code': 201, 'message': '搜索内容不能包含<或>'})
        newest_search_str = commitDataInputText
        # print(newest_search_str)
        with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "r") as f:
            lines = f.readlines()
            res=[]
            # print(lines)
            for line in lines:
                password,commitDataInputTextline = line.split(" ")
                password = aes256_decrypt(password,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
                commitDataInputTextline = aes256_decrypt(commitDataInputTextline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
                # print(password+' '+commitDataInputTextline)
                if search_text(commitDataInputTextline,commitDataInputText):
                    res.append([commitDataInputTextline,password])
            if len(res) == 0:
                return jsonify({'code': 201, 'message': '未找到'})
            else:
                dataTrans = {
                    'code': 200, 
                    'message': '传输成功'
                }
                for i in range(len(res)):
                    dataTrans['res'+str(i+1)+'password'] = res[i][1]
                    dataTrans['res'+str(i+1)+'DataText'] = res[i][0]
                dataTrans["len"]=len(res)
                return dataTrans
                
        # print(password,commitDataInputText)
@app.route("/main/passwordModify")
def passwordModify():
    if CheckLogin():
        return render_template('passwordModify.html')
    else:
        flash('请先登录', 'error')
        return redirect(url_for('login'))
    
@app.route("/main/passwordModify",methods=['POST'])
def passwordModify_post():
    if request.method == 'POST':
        data = request.get_json()
        if not CheckLogin():
            return jsonify({'code': 401, 'message': '请先登录'})
        password = data.get('password')
        commitDataInputText = data.get('commitDataInputText')
        id = data.get('id')
        # print(password,commitDataInputText)
        if '<' in password or '>' in password or '<' in commitDataInputText or '>' in commitDataInputText:
            return jsonify({'code': 401, 'message': '密码或备注不能包含<或>'})
        for i in exceptstr:
            if i in password or i in commitDataInputText:
                return jsonify({'code': 401, 'message': '密码或备注不能包含'+i})
        if not password or not commitDataInputText:
            return jsonify({'code': 401, 'message': '密码或备注不能为空'})
        write_list=[]
        with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "r") as f:
            lines = f.readlines()
            flag_have=False
            # print(lines)
            for line in lines:
                passwordline,commitDataInputTextline = line.split(" ")
                passwordline = aes256_decrypt(passwordline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
                commitDataInputTextline = aes256_decrypt(commitDataInputTextline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
                if data_ready_to_modify[id][1]==commitDataInputTextline and data_ready_to_modify[id][0]==passwordline and flag_have==False:
                    flag_have=True
                    continue
                write_list.append([passwordline,commitDataInputTextline])
        with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "w") as f:
            for i in write_list:
                f.write(aes256_encrypt(i[0],sha256_to_256_bytes(hash_string_sha3_256(session['password'])))+" "+aes256_encrypt(i[1],sha256_to_256_bytes(hash_string_sha3_256(session['password'])))+"\n")
        data_ready_to_modify[id]=[]
        with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "a") as f:
            f.write(aes256_encrypt(password,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))+" "+aes256_encrypt(commitDataInputText,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))+"\n")
        return jsonify({'code': 200, 'message': '传输成功'})
        # print(password,commitDataInputText)


@app.route("/main/passwordReadyToModify",methods=['POST'])
def passwordReadyToModify():
    data=request.get_json()
    if not CheckLogin():
        return jsonify({'code': 401, 'message': '请先登录'})
    password = data.get('password')
    commitDataInputText = data.get('commitDataInputText')
    id = data.get('id')
    with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "r") as f:
        lines = f.readlines()
        flag_have=False
        # print(lines)
        for line in lines:
            passwordline,commitDataInputTextline = line.split(" ")
            passwordline = aes256_decrypt(passwordline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
            commitDataInputTextline = aes256_decrypt(commitDataInputTextline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
            if(commitDataInputTextline==commitDataInputText and passwordline==password):
                flag_have=True
                break
    if not flag_have:
        return jsonify({'code': 401, 'message': '你神经啊，改前端是罢'})
    else:
        data_ready_to_modify[id]=[password,commitDataInputText]
        return jsonify({'code': 200, 'message': '传输成功'})
 



@app.route("/button",methods=['POST'])
def button():
    if request.method == 'POST':
        data = request.get_json()
        if not CheckLogin():
            return jsonify({'code': 401, 'message': '请先登录'})
        # print(password,commitDataInputText)
        return jsonify({'code': 200, 'message': '传输成功'})
    
@app.route("/main/passwordDel",methods=['POST'])
def passwordDel():
    global newest_search_str
    if request.method == 'POST':
        data = request.get_json()
        # print(password,commitDataInputText)
        password = data.get('password')
        commitDataInputText = data.get('commitDataInputText')
        id = data.get('id')
        Have_flag = False
        write_list = []
        with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                passwordline,commitDataInputTextline = line.split(" ")
                passwordline = aes256_decrypt(passwordline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
                commitDataInputTextline = aes256_decrypt(commitDataInputTextline,sha256_to_256_bytes(hash_string_sha3_256(session['password'])))
                if(commitDataInputTextline==commitDataInputText and passwordline==password and not Have_flag):
                    Have_flag=True
                    continue
                write_list.append([passwordline,commitDataInputTextline])
        if not Have_flag:
            return jsonify({'code': 401, 'message': '你神经啊，改前端是罢'})
        else:
            with open(GetCurrentPath()+"data\\"+session.get('account')+".txt", "w") as f:
                for i in range(len(write_list)):
                    f.write(aes256_encrypt(write_list[i][0],sha256_to_256_bytes(hash_string_sha3_256(session['password'])))+" "+aes256_encrypt(write_list[i][1],sha256_to_256_bytes(hash_string_sha3_256(session['password'])))+"\n")
            dataTrans = {
                    'code': 200, 
                    'message': '传输成功'
                    }
            i=0
            for j in write_list:
                if(search_text(j[1],newest_search_str)):
                    # print(j[1],newest_search_str)
                    dataTrans['res'+str(i+1)+'password'] = j[0]
                    dataTrans['res'+str(i+1)+'DataText'] = j[1]
                    i+=1
            dataTrans["len"]=i
            return dataTrans


if __name__ == '__main__':
    app.run(host="127.0.0.1",port=7070,debug=True)