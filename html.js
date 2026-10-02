// sVn Pro payments via Paystack (TEST mode while you use an sk_test_ key).
// The secret key lives only in Firebase Secret Manager: PAYSTACK_SECRET_KEY.
const {onCall,onRequest,HttpsError}=require('firebase-functions/v2/https');
const {defineSecret}=require('firebase-functions/params');
const admin=require('firebase-admin');const crypto=require('crypto');
admin.initializeApp();
const db=admin.firestore(),T=admin.firestore.Timestamp,FV=admin.firestore.FieldValue;
const KEY=defineSecret('PAYSTACK_SECRET_KEY');
const PRICE_KOBO=100000,CUR='NGN',DAYS=30,SITE='https://deve-ajx.github.io/Diz-Dat/';

const paystack=async(path,opt={})=>{
  const r=await fetch('https://api.paystack.co'+path,{...opt,headers:{Authorization:'Bearer '+KEY.value(),'Content-Type':'application/json'}});
  return r.json();
};

// Verify with Paystack, check amount/currency/owner, then fulfil exactly once.
async function fulfil(ref){
  const pr=db.doc('proPayments/'+ref),snap=await pr.get();
  if(!snap.exists)return 'unknown';
  const p=snap.data();
  if(p.fulfilled)return 'success';
  const j=await paystack('/transaction/verify/'+encodeURIComponent(ref)),d=j&&j.data;
  if(!j||!j.status||!d)return 'pending';
  if(d.status==='failed'){await pr.update({status:'failed'});return 'failed';}
  if(d.status!=='success')return 'pending';
  if(d.amount!==PRICE_KOBO||d.currency!==CUR||d.reference!==ref||(d.metadata&&d.metadata.uid&&d.metadata.uid!==p.uid)){
    await pr.update({status:'rejected',note:'amount, currency or owner mismatch'});return 'rejected';
  }
  await db.runTransaction(async t=>{
    const fresh=await t.get(pr);if(fresh.data().fulfilled)return;       // idempotent
    const ur=db.doc('users/'+p.uid),u=await t.get(ur);if(!u.exists)throw new Error('user missing');
    const now=Date.now(),cur=(u.data().premiumExpiresAt&&u.data().premiumExpiresAt.toMillis())||0;
    const active=cur>now,start=active?cur:now,exp=start+DAYS*864e5;
    const cust=(d.customer&&d.customer.customer_code)||'';
    t.update(pr,{status:'success',fulfilled:true,paidAt:T.fromMillis(new Date(d.paid_at||now).getTime()),proStartsAt:T.fromMillis(start),proExpiresAt:T.fromMillis(exp),paystackCustomerCode:cust,fulfilledAt:FV.serverTimestamp()});
    t.update(ur,{premium:true,premiumSource:'paystack',premiumPlan:'pro_monthly',premiumStartedAt:active&&u.data().premiumStartedAt?u.data().premiumStartedAt:T.fromMillis(now),premiumExpiresAt:T.fromMillis(exp),lastPaymentReference:ref,paystackCustomerCode:cust,updatedAt:FV.serverTimestamp()});
  });
  return 'success';
}

exports.initProPayment=onCall({secrets:[KEY]},async req=>{
  if(!req.auth)throw new HttpsError('unauthenticated','Sign in first.');
  const uid=req.auth.uid,email=req.auth.token.email;
  if(!email)throw new HttpsError('failed-precondition','Your account has no email.');
  const ref='svnpro_'+uid.slice(0,8)+'_'+crypto.randomBytes(8).toString('hex');
  await db.doc('proPayments/'+ref).set({uid,email,amount:PRICE_KOBO,currency:CUR,plan:'pro_monthly',status:'pending',fulfilled:false,createdAt:FV.serverTimestamp()});
  const j=await paystack('/transaction/initialize',{method:'POST',body:JSON.stringify({email,amount:PRICE_KOBO,currency:CUR,reference:ref,callback_url:SITE+'?pay='+ref,metadata:{uid,plan:'pro_monthly'}})});
  if(!j.status||!j.data)throw new HttpsError('internal','Could not start payment.');
  return {url:j.data.authorization_url,reference:ref};
});

// Used when the user returns from checkout (backup to the webhook). Still verified server-side.
exports.verifyProPayment=onCall({secrets:[KEY]},async req=>{
  if(!req.auth)throw new HttpsError('unauthenticated','Sign in first.');
  const ref=String((req.data&&req.data.reference)||'');
  const s=await db.doc('proPayments/'+ref).get();
  if(!s.exists||s.data().uid!==req.auth.uid)throw new HttpsError('permission-denied','Unknown payment.');
  return {status:await fulfil(ref)};
});

exports.paystackWebhook=onRequest({secrets:[KEY]},async(req,res)=>{
  const sig=req.get('x-paystack-signature')||'';
  const h=crypto.createHmac('sha512',KEY.value()).update(req.rawBody).digest('hex');
  const a=Buffer.from(h),b=Buffer.from(sig);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).send('invalid signature');
  const ev=req.body||{};
  if(ev.event==='charge.success'&&ev.data&&ev.data.reference){
    try{await fulfil(ev.data.reference);}catch(e){console.error(e);return res.status(500).send('retry');}
  }
  res.sendStatus(200);
});
