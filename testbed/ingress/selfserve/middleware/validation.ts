import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import { createHmac, randomBytes } from "crypto";

// Validation schemas
export const PfSignatureSchema = z.object({
  tenant: z.string().min(1),
  user_id: z.string().min(1),
  capabilities: z.array(z.string()).min(1),
  nonce: z.string().min(16),
  expires_at: z.string().datetime(),
  signature: z.string().min(1),
});

export const AccessReceiptSchema = z.object({
  tenant: z.string().min(1),
  subject: z.string().min(1),
  shard: z.string().min(1),
  query_hash: z.string().min(1),
  result_hash: z.string().min(1),
  nonce: z.string().min(16),
  expires_at: z.string().datetime(),
  signature: z.string().min(1),
});

export const RequestValidationSchema = z.object({
  pf_signature: PfSignatureSchema,
  access_receipts: z.array(AccessReceiptSchema).optional(),
});

// Error response types
export interface ValidationError {
  code: string;
  message: string;
  details?: any;
}

export const VALIDATION_ERROR_CODES = {
  PF_SIG_INVALID: "PF_SIG_INVALID",
  PF_SIG_EXPIRED: "PF_SIG_EXPIRED",
  PF_SIG_MISSING: "PF_SIG_MISSING",
  ACCESS_RECEIPT_INVALID: "ACCESS_RECEIPT_INVALID",
  ACCESS_RECEIPT_EXPIRED: "ACCESS_RECEIPT_EXPIRED",
  ACCESS_RECEIPT_MISSING: "ACCESS_RECEIPT_MISSING",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  TENANT_NOT_FOUND: "TENANT_NOT_FOUND",
} as const;

// Validation middleware class
export class ValidationMiddleware {
  private readonly secretKey: string;
  private readonly algorithm = "sha256";

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  // Main validation middleware
  public validateRequest = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      // Ensure request ID is set
      if (!res.locals["requestId"]) {
        res.locals["requestId"] = (req.headers["x-request-id"] as string) || "unknown";
      }

      // Extract and validate PF signature
      const pfSignature = req.headers["x-pf-signature"] as string;
      if (!pfSignature) {
        this.sendError(res, 403, VALIDATION_ERROR_CODES.PF_SIG_MISSING, "PF signature is required");
        return;
      }

      // Parse and validate PF signature
      const parsedSignature = this.parseAndValidatePfSignature(pfSignature);
      if (!parsedSignature.success) {
        this.sendError(
          res,
          403,
          VALIDATION_ERROR_CODES.PF_SIG_INVALID,
          parsedSignature.error || "Unknown error",
        );
        return;
      }

      // Check if signature is expired
      if (this.isSignatureExpired(parsedSignature.data.expires_at)) {
        this.sendError(res, 403, VALIDATION_ERROR_CODES.PF_SIG_EXPIRED, "PF signature has expired");
        return;
      }

      // Verify signature authenticity
      if (!this.verifySignature(parsedSignature.data)) {
        this.sendError(res, 403, VALIDATION_ERROR_CODES.PF_SIG_INVALID, "Invalid signature");
        return;
      }

      // Validate access receipts if present
      const accessReceipts = req.headers["x-access-receipts"] as string;
      if (accessReceipts) {
        const receiptsValidation = this.validateAccessReceipts(
          accessReceipts,
          parsedSignature.data.tenant,
        );
        if (!receiptsValidation.success) {
          this.sendError(
            res,
            403,
            receiptsValidation.errorCode || VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID,
            receiptsValidation.error || "Unknown error",
          );
          return;
        }
      }

      // Add validated data to request
      req.pfSignature = parsedSignature.data;
      req.tenant = parsedSignature.data.tenant;
      req.userId = parsedSignature.data.user_id;
      req.capabilities = parsedSignature.data.capabilities;

      next();
    } catch (error) {
      console.error("Validation error:", error);
      this.sendError(res, 500, "INTERNAL_ERROR", "Internal validation error");
    }
  };

  // Parse and validate PF signature
  private parseAndValidatePfSignature(signature: string): {
    success: boolean;
    data?: any;
    error?: string;
  } {
    try {
      const decoded = Buffer.from(signature, "base64").toString("utf-8");
      const parsed = JSON.parse(decoded);

      const validation = PfSignatureSchema.safeParse(parsed);
      if (!validation.success) {
        return { success: false, error: "Invalid signature schema" };
      }

      return { success: true, data: validation.data };
    } catch (error) {
      console.error("Signature parsing error:", error);
      return { success: false, error: "Failed to parse signature" };
    }
  }

  // Validate access receipts
  private validateAccessReceipts(
    receiptsHeader: string,
    expectedTenant: string,
  ): {
    success: boolean;
    errorCode?: string;
    error?: string;
  } {
    try {
      const receipts = JSON.parse(receiptsHeader);

      if (!Array.isArray(receipts)) {
        return {
          success: false,
          errorCode: VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID,
          error: "Invalid receipts format",
        };
      }

      for (const receipt of receipts) {
        // Validate schema
        const validation = AccessReceiptSchema.safeParse(receipt);
        if (!validation.success) {
          return {
            success: false,
            errorCode: VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID,
            error: "Invalid receipt schema",
          };
        }

        // Check tenant consistency
        if (receipt.tenant !== expectedTenant) {
          return {
            success: false,
            errorCode: VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID,
            error: "Receipt tenant mismatch",
          };
        }

        // Check expiration
        if (this.isSignatureExpired(receipt.expires_at)) {
          return {
            success: false,
            errorCode: VALIDATION_ERROR_CODES.ACCESS_RECEIPT_EXPIRED,
            error: "Receipt has expired",
          };
        }

        // Verify receipt signature
        if (!this.verifyReceiptSignature(receipt)) {
          return {
            success: false,
            errorCode: VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID,
            error: "Invalid receipt signature",
          };
        }
      }

      return { success: true };
    } catch (error) {
      return {
        success: false,
        errorCode: VALIDATION_ERROR_CODES.ACCESS_RECEIPT_INVALID,
        error: "Failed to parse receipts",
      };
    }
  }

  // Check if signature is expired
  private isSignatureExpired(expiresAt: string): boolean {
    const expiryDate = new Date(expiresAt);
    const now = new Date();
    return now > expiryDate;
  }

  // Verify PF signature
  private verifySignature(signatureData: any): boolean {
    try {
      const { signature, ...dataToSign } = signatureData;
      const dataString = JSON.stringify(dataToSign, Object.keys(dataToSign).sort());

      const expectedSignature = createHmac(this.algorithm, this.secretKey)
        .update(dataString)
        .digest("hex");

      return signature === expectedSignature;
    } catch (error) {
      console.error("Signature verification error:", error);
      return false;
    }
  }

  // Verify receipt signature
  private verifyReceiptSignature(receipt: any): boolean {
    try {
      const { signature, ...dataToSign } = receipt;
      const dataString = JSON.stringify(dataToSign, Object.keys(dataToSign).sort());

      const expectedSignature = createHmac(this.algorithm, this.secretKey)
        .update(dataString)
        .digest("hex");

      return signature === expectedSignature;
    } catch (error) {
      return false;
    }
  }

  // Send structured error response
  private sendError(
    res: Response,
    statusCode: number,
    code: string,
    message: string,
    details?: any,
  ): void {
    const errorResponse: ValidationError = {
      code,
      message,
      details,
    };

    res.status(statusCode).json({
      error: errorResponse,
      timestamp: new Date().toISOString(),
      request_id: res.locals["requestId"] || "unknown",
    });
  }

  // Generate PF signature for testing
  public generateSignature(data: {
    tenant: string;
    user_id: string;
    capabilities: string[];
    expires_in: number;
  }): string {
    const expiresAt = new Date(Date.now() + data.expires_in * 1000).toISOString();
    const nonce = randomBytes(16).toString("hex");

    // Create signature data without expires_in (since it's not part of the final structure)
    const signatureData = {
      tenant: data.tenant,
      user_id: data.user_id,
      capabilities: data.capabilities,
      nonce,
      expires_at: expiresAt,
    };

    const dataString = JSON.stringify(signatureData, Object.keys(signatureData).sort());

    const signature = createHmac(this.algorithm, this.secretKey).update(dataString).digest("hex");

    const fullData = { ...signatureData, signature };
    const base64Data = Buffer.from(JSON.stringify(fullData)).toString("base64");

    return base64Data;
  }

  // Generate access receipt for testing
  public generateAccessReceipt(data: {
    tenant: string;
    subject: string;
    shard: string;
    query_hash: string;
    result_hash: string;
    expires_in: number;
  }): any {
    const expiresAt = new Date(Date.now() + data.expires_in * 1000).toISOString();
    const nonce = randomBytes(16).toString("hex");

    const receiptData = {
      ...data,
      nonce,
      expires_at: expiresAt,
    };

    const dataString = JSON.stringify(receiptData, Object.keys(receiptData).sort());
    const signature = createHmac(this.algorithm, this.secretKey).update(dataString).digest("hex");

    return { ...receiptData, signature };
  }
}

// Rate limiting middleware per tenant
export class TenantRateLimiter {
  private limits: Map<string, { count: number; resetTime: number }> = new Map();
  private readonly windowMs: number;
  private readonly maxRequests: number;

  constructor(windowMs: number = 15 * 60 * 1000, maxRequests: number = 100) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  public limitByTenant = (req: Request, res: Response, next: NextFunction): void => {
    const tenant = req.tenant;
    if (!tenant) {
      next();
      return;
    }

    const now = Date.now();
    const limit = this.limits.get(tenant);

    if (!limit || now > limit.resetTime) {
      // Reset or create new limit
      this.limits.set(tenant, {
        count: 1,
        resetTime: now + this.windowMs,
      });
      next();
      return;
    }

    if (limit.count >= this.maxRequests) {
      res.status(429).json({
        error: {
          code: VALIDATION_ERROR_CODES.RATE_LIMIT_EXCEEDED,
          message: "Rate limit exceeded for tenant",
          details: {
            tenant,
            limit: this.maxRequests,
            window_ms: this.windowMs,
            reset_time: new Date(limit.resetTime).toISOString(),
          },
        },
        timestamp: new Date().toISOString(),
        request_id: res.locals["requestId"] || "unknown",
      });
      return;
    }

    limit.count++;
    next();
  };

  // Clean up expired limits
  public cleanup(): void {
    const now = Date.now();
    for (const [tenant, limit] of this.limits.entries()) {
      if (now > limit.resetTime) {
        this.limits.delete(tenant);
      }
    }
  }
}

// Request ID middleware
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const requestId = (req.headers["x-request-id"] as string) || randomBytes(8).toString("hex");
  res.locals["requestId"] = requestId;
  req.headers["x-request-id"] = requestId;
  next();
};

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      pfSignature?: any;
      tenant?: string;
      userId?: string;
      capabilities?: string[];
    }
  }
}
