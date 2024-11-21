const express = require('express')
//开启服务
const app = express()
//获取post数据
app.use(express.urlencoded({extended:true}))
//处理json请求
app.use(express.json())


app.all('*',function(req,res,next){
    res.header("Access-Control-Allow-Origin","*");
    res.header("Access-Control-Allow-Headers","*")
    next()
})

//设置跨域
function setHeader(req,res,next){
    // 设置允许请求的请求头
    res.header("Access-Control-Allow-Headers","*")
    // 设置允许访问的地址，默认只有同源能访问，设置允许跨域,允许所有请求地址访问
    res.header("Access-Control-Allow-Origin","*");
    next()    
}

//开放一个 延迟返回数据的接口
app.all('/sendload',[setHeader,(req,res)=>{
    setTimeout(()=>{
        sendData(req,res)
    },2000)
}])

//统一返回
function sendData(req,res){ 
    let data = {
        method : req.method,//请求方式
        url : req.url, //请求地址
        query : req.query, //get请求参数信息
        body : req.body, //post请求参数信息
        txt : '请求成功了'
    }
    res.send(JSON.stringify(data))
}

//开放 http://localhost:3344/xmlget|jqget|fetchget|axiosget 发送 get请求
app.get('/xmlget|jqget|fetchget|axiosget',[setHeader,(req,res)=>{
    sendData(req,res)
}])


//开放 http://localhost:3344/xmlpost|jqpost|fetchpost|axiopost 发送 post 请求
app.post('/xmlpost|jqpost|fetchpost|axiopost',(req,res)=>{
    // sendData(req,res)
    sendData(req,res)
})



//开放一个未设置跨域的接口
app.get('/cors',(req,res)=>{
    sendData(req,res)
})

//开放一个jsonp跨域接口
app.get('/jsonp',(req,res)=>{
    let data = {
        method : req.method,
        list : ['list1','list2','list3','list4','list5','list6','list6'],
        url : req.url,
        txt : 'jsonp请求成功了'
    }
    res.send(`callback(${JSON.stringify(data)})`)
})

app.listen('3344',()=>{console.log('http://localhost:3344 服务已开启')})