class CreateUsers < ActiveRecord::Migration[7.0]
  def change
    create_table :users do |t|

      t.timestamps
      t.string :email, null:false, unique:true
      t.string :password_digest, null:false
      t.string :session_token, null:false, unique:true
    end
    add_index :users, :email
    add_index :users, :password_digest
    add_index :users, :session_token
  end
end
