package org.lucky0111.pettalk.domain.entity.review;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.*;
import org.lucky0111.pettalk.domain.common.BaseTimeEntity;
import org.lucky0111.pettalk.domain.entity.match.UserApply;

@Setter
@Getter
@Entity
@Table(name = "reviews", indexes = {
        @Index(name = "idx_review_apply", columnList = "apply_id"),
        @Index(name = "idx_review_rating", columnList = "rating")
})
@NoArgsConstructor
public class Review extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long reviewId;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "apply_id")
    private UserApply userApply;

    @Column(nullable = false)
    @Min(1)
    @Max(5)
    private Integer rating;

    private String reviewImageUrl;

    @Column(nullable = false)
    private String comment;
}
