<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class ResetPasswordMail extends Mailable
{
    use Queueable, SerializesModels;

    public $verificationToken;
    public $email;

    /**
     * Create a new message instance.
     *
     * @param string $verificationToken
     * @param string $email
     * @return void
     */
    public function __construct($verificationToken, $email)
    {
        $this->verificationToken = $verificationToken;
        $this->email = $email;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        return $this->subject('Reset Password')
            ->view('auth-mail.reset_password')
            ->with([
                'verificationKey' => $this->verificationToken,
                'email' => $this->email
            ]);
    }
}
