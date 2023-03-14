require 'bcrypt'

class User < ApplicationRecord


    validates :email, :session_token, :password_digest, presence: true
    before_validation :ensure_session_token

    attr_reader :password

    def self.find_by_credentials(email, password)
        user = user.find_by(email: email)

        if user && user.is_password_?(user)
            return user
        else 
            return nil
        end

    end

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end


    def is_password?(password)
        bcrypt_object = BCrypt::Password.new(self.password_digest)
        bcrypt_object.is_password?(password)

    end

    def reset_session_token
        self.session_token = generate_unique_session_token
        self.save
        self.session_token
    end


    private
    def generate_unique_session_token
     
        token = SecureRandom::urlsafe_base64
        # debugger
        while User.exists?(session_token: token)
             token = SecureRandom::urlsafe_base64
        end
        token
    end
    def ensure_session_token
        self.session_token ||= generate_unique_session_token
    end
end

