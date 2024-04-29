<!DOCTYPE html>
<html>
<head>
    <title>Verification Code</title>
</head>
<body>
    <div
        style="text-align:center; font-family: Segoe UI; width: 500px; margin: auto auto; padding: 56px; box-shadow: 0 4px 4px 0 rgba(233, 240, 243, 0.4); border: 1px solid #ECEFF3; border-radius: 12px;">
        <div style="text-align: center;">
            <img src="http://localhost:5173/src/assets/images/logo/rj-logo.png" alt="Logo"
                style="width:150px; margin-left:auto; margin-right:auto;">
        </div>
        
        <p style="font-weight: 400; font-size: 16px;">Thank you for signing up for our service. To complete the
            verification process, please use the following code: </p>
            <span style="font-size: 32px; font-weight: 600; margin: 0;">{{
                $verification_code ?? '' }}</span>
        <p style="font-weight: 400; font-size: 16px;">If you did not request this verification code, please ignore this
            message.</p>

        <div style="display:flex; width:100%; justify-content:space-between">
            <div >
                <div>
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24">
                        <path fill="black"
                            d="M22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6zm-2 0l-8 5l-8-5h16zm0 12H4V8l8 5l8-5v10z" />
                    </svg>
                    <label>admin@rj.com</label>
                </div>
                <div>
                    <svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 384 512" height="16px" width="16px" xmlns="http://www.w3.org/2000/svg"><path d="M80 0C44.7 0 16 28.7 16 64V448c0 35.3 28.7 64 64 64H304c35.3 0 64-28.7 64-64V64c0-35.3-28.7-64-64-64H80zm80 432h64c8.8 0 16 7.2 16 16s-7.2 16-16 16H160c-8.8 0-16-7.2-16-16s7.2-16 16-16z"></path></svg>
                    <label>09123456789</label>
                </div>
            </div>

            <div>
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24">
                    <path fill="currentColor"
                        d="M22 12c0-5.52-4.48-10-10-10S2 6.48 2 12c0 4.84 3.44 8.87 8 9.8V15H8v-3h2V9.5C10 7.57 11.57 6 13.5 6H16v3h-2c-.55 0-1 .45-1 1v2h3v3h-3v6.95c5.05-.5 9-4.76 9-9.95z" />
                </svg>
                <a href="https://www.facebook.com/" style="text-decoration: none; color:black">facebook.com/rj</a>
            </div>
        </div>
    </div>
</body>
</html>
