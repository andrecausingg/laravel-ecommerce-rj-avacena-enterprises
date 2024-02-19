<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class LogsModel extends Model
{
    use HasFactory;
    protected $table = 'logs_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'user_id_hash',
        'ip_address',
        'user_action',
        'details',
        'user_device',
        'deleted_at',
        'created_at',
        'updated_at',
    ];
}
