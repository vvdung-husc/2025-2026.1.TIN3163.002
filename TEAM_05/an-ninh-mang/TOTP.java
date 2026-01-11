// Import thư viện tạo HMAC
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// Import ByteBuffer để chuyển số long mảng byte
import java.nio.ByteBuffer;
// Import Scanner để nhập dữ liệu từ bàn phím
import java.util.Scanner;

public class TOTP {

    // Khoảng thời gian hiệu lực của mỗi OTP (30 giây)
    private static final long TIME_STEP = 30;
    // Số chữ số của OTP (6 số)
    private static final int OTP_DIGITS = 6;
    // Thuật toán băm HMAC-SHA1 theo chuẩn RFC 6238
    private static final String HMAC_ALGO = "HmacSHA1";

    /**
     * ================== HÀM SINH OTP ==================
     * @param secretKey khóa bí mật dùng để sinh OTP
     * @return chuỗi OTP gồm 6 chữ số
     */
    public static String generateTOTP(String secretKey) throws Exception {

        // Lấy thời gian hiện tại (tính bằng giây)
        long currentTime = System.currentTimeMillis() / 1000;
        // Tính bộ đếm thời gian T = UnixTime / 30
        long timeCounter = currentTime / TIME_STEP;

        // Chuyển timeCounter (long) thành mảng 8 byte
        byte[] data = ByteBuffer.allocate(8)
                                .putLong(timeCounter)
                                .array();

        // Tạo khóa bí mật cho HMAC
        SecretKeySpec signKey = new SecretKeySpec(secretKey.getBytes(), HMAC_ALGO);
        
        // Khởi tạo đối tượng Mac với thuật toán HMAC-SHA1
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(signKey);

        // Tính HMAC của bộ đếm thời gian
        byte[] hash = mac.doFinal(data);

        // ================== DYNAMIC TRUNCATION ==================

        // Lấy offset từ 4 bit cuối của byte cuối cùng
        int offset = hash[hash.length - 1] & 0x0F;

        // Ghép 4 byte liên tiếp thành số nguyên 31 bit
        int binary =
                ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        // Lấy 6 chữ số cuối
        int otp = binary % (int) Math.pow(10, OTP_DIGITS);

        // Trả về OTP đủ 6 chữ số (có thể có số 0 ở đầu)
        return String.format("%0" + OTP_DIGITS + "d", otp);
    }

    /**
     * ================== HÀM XÁC THỰC OTP ==================
     * @param secretKey khóa bí mật
     * @param userOTP OTP do người dùng nhập
     * @return true nếu OTP đúng, false nếu sai
     */
    public static boolean verifyTOTP(String secretKey, String userOTP) throws Exception {
        // Sinh OTP hiện tại từ hệ thống
        String currentOTP = generateTOTP(secretKey);
        // So sánh OTP hệ thống với OTP người dùng
        return currentOTP.equals(userOTP);
    }

    /**
     * ================== HÀM MAIN ==================
     * Chạy chương trình
     */
    public static void main(String[] args) throws Exception {

        Scanner sc = new Scanner(System.in);
        // Khóa bí mật (thường được lưu ở server)
        String secretKey = "MY_SECRET_KEY";

        // Sinh OTP hiện tại
        String otp = generateTOTP(secretKey);
        System.out.println("OTP hiện tại: " + otp);

        // Nhập OTP từ người dùng
        System.out.print("Nhập OTP để xác thực: ");
        String inputOTP = sc.nextLine();

        // Kiểm tra OTP
        if (verifyTOTP(secretKey, inputOTP)) {
            System.out.println(" OTP hợp lệ!");
        } else {
            System.out.println(" OTP không hợp lệ!");
        }
    }
}