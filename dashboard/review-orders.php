<?php
session_start();
include_once '../utils/jwt-auth.php';
include '../utils/conn.php';
include '../utils/select_data.php';

$logedin = false;
$user_id = 0;

if (checkIsLogedIn() && isAdmin() || isChef()) {
    $logedin = true;
    $user = verifyJWT($_COOKIE['jwt-token']);
    if ($user != null) {
        $user_id = $user['user_id'];
    } else {
        header("Location:./menu.php", true, 403);
    }
} else {
    header("Location:../index.php");
}

?>

<html lang="en">

<head>
  <title>Online Food Ordering System-Review Orders</title>
  <link rel="stylesheet" href="../assets/css/cart.css">
  <link rel="stylesheet" href="../assets/css/order.css">
  <?php include '../includes/header.php'?>

  <style>
    .form-control{
      border:none;
      padding: 0;
      height: 10px;
      padding-left: 10px;
    }
    .btn{
      padding: 5px;
    }
    .btn:hover{
      padding: 5px 10px;
    }
  </style>
</head>

<body>

    <nav class="container-fluid  px-4 d-flex flex-row navbar-div justify-content-between ">
      <h1 class="brand-name text-danger">Online Food Ordering System</h1>

      <ul id="navbar" class="navbar "> <!-- put navbar class  d-none   d-sm-flex -->
        <li class="nav_item " ><a href="../index.php" class="d-flex">
          <i class="fa-solid fa-house"></i>
        </a></li>
        <li class="nav_item " ><a href="" class="d-flex">
          <i class="fa-solid fa-chalkboard-user"></i>
        </a></li>

        <li class="nav_item" ><a href="./menu-items.php"><i class="fa-solid fa-list "></i></a></li>
        <li class="nav_item" ><a href="./view-chef.php?view=all"><i class="fa-solid fa-users "></i></a></li>
      </ul>
        

      </ul>
      
    </nav>

    <style>
          .custom-alert{
          
          padding: 15px;
          text-transform: capitalize;
          

          }
          .suc-error{
            border: 0.8px solid green;
            background-color: rgba(32, 125, 58, 0.3);
          }
          .error{
            border: 0.8px solid red;
            background-color: rgba(255, 0, 0, 0.09);
          }
          .warning{
            border: 0.8px solid yellow;
            background-color: rgb(247, 207, 47,0.5);
          }
          tr.tr-head>th{
            font-size: 1.1em;
            font-weight: 500;
          }
    </style>

    <div class="container">
      <?php

        if(isset($_SESSION['error'])){?>
          <div class="container error-div my-2">
            <div class="row">
              <div class="col-10 col-md-6 mx-auto">
                <p class="custom-alert text-center error"><?= $_SESSION['error']?></p>
              </div>
            </div>
          </div>

          
        <?php $_SESSION['error']=null; }else if(isset($_SESSION['suc'])){?>
          <div class="container error-div my-2">
            <div class="row">
              <div class="col-10 col-md-6 mx-auto">
                <p class="custom-alert text-center suc-error"><?= $_SESSION['suc']?></p>
              </div>
            </div>
          </div>

        <?php $_SESSION['suc'] = null;}else if(isset($_SESSION['warning'])){?>
          <div class="container error-div my-2">
            <div class="row">
              <div class="col-10 col-md-6 mx-auto">
                <p class="custom-alert text-center suc-error"><?= $_SESSION['warning']?></p>
              </div>
            </div>
          </div>
          
        <?php $_SESSION['warning'] = null; }?>

    </div>
    
    <div class="container " style='position:relative;'>
        
        <div class="container d-none" id="status-msg" style='position: absolute;left: 50%;
          transform: translate(-50%, 0);'>
          <div class="row">
            <div class="col-10 col-md-6 mx-auto">
              <p class="alert alert-success text-center">
                Staus updated!
              </p>
            </div>
          </div>
        </div>  

        <div class="container d-none" id="status-msg-error" style='position: absolute;left: 50%;
          transform: translate(-50%, 0);'>
          <div class="row">
            <div class="col-10 col-md-6 mx-auto">
              <p class="alert alert-danger text-center">
                Staus updated faild!
              </p>
            </div>
          </div>
        </div>  

      <div class="row">
        <div class="col-12">
          <p class="display-6 text-center mt-3">Upcomming Orders.</p>

          <table class="table table-hover">
            <thead class='mb-3'>
              <tr class="tr-head  text-center " style="background-color: rgba(136, 138, 137,0.5);">
                <th class='d-none d-md-flex'>ID</th>
                <th>Order Date</th>
                <th>Total</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody class="text-center">

              <?php

              $sql = "SELECT * FROM orders ORDER BY order_date DESC";
              $res = $conn->query($sql);
              if($res==TRUE){
                if($res->num_rows>0){
                  while($row=$res->fetch_assoc()){?>
                    <tr class=''>
                      <td class='d-none d-md-flex'><?= $row['order_id']?></td>
                      <td><?= explode(' ',$row['order_date'])[0] ?></td>
                      <td>RS. <?=number_format($row['total'], 2, '.', ',')?></td>
                      <td style="opacity: 0.9;" >
                          <form class='d-flex update-form m-0'>
                            <input type="hidden" name="orderid" value='<?= $row['order_id']?>'>
                            <select  name="status" class=' form-control form-control-sm status-value'>
                              <?php
                              
                              switch($row['status']){
                                  case 0:
                                    echo
                                      '
                                    <option value="0" selected >Not Approved</option>
                                    <option value="1">Approved</option>
                                    <option value="2">In Processing</option>
                                    <option value="3">In Dilevary</option>
                                    <option value="4">Completed</option>
                                    ';
                                    break;
                                  case 1:
                                    echo
                                      '
                                    <option value="0"  >Not Approved</option>
                                    <option value="1" selected>Approved</option>
                                    <option value="2">In Processing</option>
                                    <option value="3">In Dilevary</option>
                                    <option value="4">Completed</option>
                                    ';
                                    break;
                                  case 2:
                                    echo '
                                    <option value="0">Not Approved</option>
                                    <option value="1">Approved</option>
                                    <option value="2" selected >In Processing</option>
                                    <option value="3">In Dilevary</option>
                                    <option value="4">Completed</option>';
                                    break;
                                  case 3:
                                    echo '
                                    <option value="0">Not Approved</option>
                                    <option value="1">Approved</option>
                                    <option value="2" >In Processing</option>
                                    <option value="3" selected >In Dilevary</option>
                                    <option value="4">Completed</option>';
                                    break;
                                  case 4:
                                    echo '
                                    <option value="0">Not Approced</option>
                                    <option value="1">Approced</option>
                                    <option value="2"  >In Processing</option>
                                    <option value="3">In Dilevary</option>
                                    <option value="4" selected >Completed</option>';
                                    break;


                              }
                              
                              
                              ?>
                            </select>

                            <button type="submit" name='save' class='btn btn-sm btn-success status-update-btn'>
                              Update
                            </button>

                          </form>
                       
                      </td>
                      <td>
                        <button type="button" class="btn w-100 btn-sm btn-info m-0 fa-solid fa-eye bg-transparent border-0" data-bs-toggle="modal" data-bs-target="#exampleModal<?= $row['order_id']?>">
                        </button>
                      </td>
                    </tr>

                    <!-- Modal -->
                    <div class="modal fade modal-lg" id="exampleModal<?= $row['order_id']?>" tabindex="-1" aria-labelledby="exampleModal<?= $row['order_id']?>Label" aria-hidden="true">
                      <div class="modal-dialog">
                        <div class="modal-content">
                          <div class="modal-header">
                            <h5 class="modal-title" id="exampleModal<?= $row['order_id']?>Label">Order <?= $row['order_id']?></h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                          </div>
                          <div class="modal-body m-0 p-0">
                            
                            <article class="card">
                              <div class="card-body">
                                <p>Order Content</p>

                                <ul class="row " style='overflow-x:scroll;'>
                                  <?= getOrderItems($conn,$row['order_id']) ?>
                                  
                                </ul>
                                <hr>
                                <p>Options.</p>
                              </div>
                            </article>
                               
                          </div>
                          
                          <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                          </div>
                        </div>
                      </div>
                    </div>
                    

                  <?php }

                }else{?>
                <tr>
                  <td class="text-center text-warning">No orders found!</td>
                </tr>
              <?php }

              }else{?>
                <tr>
                  <td class="text-center text-warning">Error</td>
                </tr>
              <?php }



              ?>
              
            </tbody>
          </table>

        </div>
      </div>
    </div>
    
    <script>

      document.addEventListener("DOMContentLoaded",()=>{



        let updateform=document.querySelectorAll('.update-form')
        updateform.forEach(form=>{

          form.addEventListener('submit',(e)=>{
            e.preventDefault()
            e.target.save.setAttribute('disabled','')
            let orderid=e.target.orderid.value;
            let staus=e.target.status.value;


            const xhr=new XMLHttpRequest()

            xhr.open('POST',"../actions/placeOrderAction.php")
            xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded")

            xhr.onreadystatechange=function(){
                if (this.readyState == 4 && this.status == 200) {
                  if(this.responseText==='1'){

                    e.target.status.selectedIndex=staus

                    document.getElementById('status-msg').classList.remove('d-none')
                    
                  }else{
                    document.getElementById('status-msg-error').classList.remove('d-none')
                  }

                  setInterval(()=>{
                    removemsg()
                  },1000)

                  e.target.save.removeAttribute('disabled','')
              }
            }

            xhr.send(`order_id=${orderid}&changeStatus=true&changeTo=${staus}`)

            

          })
        })

        

        setTimeout(() => {
          let error=document.querySelector('.error-div');
          if(error){
            
            error.remove()
          }
        }, 2000);

      })

      function removemsg(){

        let msg=document.getElementById('status-msg')
        let ermsg=document.getElementById('status-msg-error')
        if(msg){
          
          msg.classList.add('d-none')
        }

        if(ermsg){
          ermsg.classList.add('d-none')
        }
      }
    </script>

    <script src="../assets/js/cart.js"></script>
  <?php
  include_once '../includes/footer.php';
  include_once '../includes/scripts.php';
  ?>
</body>
</html>