<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class VerificationMail extends Mailable
{
    use Queueable, SerializesModels;

    public $verification_code;
    public $name;

    /**
     * Create a new message instance.
     *
     * @param string $verification_code
     * @param string $name
     * @return void
     */
    public function __construct($verification_code, $name)
    {
        $this->verification_code = $verification_code;
        $this->name = $name;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        return $this->subject('Verification Mail')
            ->view('auth-mail.verification_mail')
            ->with([
                'name' => $this->name,
                'verification_code' => $this->verification_code,
            ]);
    }
}

?>